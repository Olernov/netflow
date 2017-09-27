#include "v9packet.h"
#include "main.h"

extern void UnixTimeToStr(
    uint32_t p_dwUnixTime,
    char *m_pmcOutputStr,
    size_t p_stMaxChars);

extern void CopyBlock(
    uint8_t *p_pmbDst,
    size_t p_stDstSize,
    uint8_t *p_pmbSrc,
    size_t p_stBytesToCopy);


V9Packet::V9Packet(CNFParser* nfParser) :
    NFPacket(NETFLOW_V9, nfParser)
{}

bool V9Packet::ParseHeader()
{
    uint8_t* buffer;
    const size_t bytesToRead = HEADER_SIZE - VERSION_FIELD_SIZE;
    size_t bytesRead = nfParser->m_pcoFileReader->ReadData(&buffer, bytesToRead);

    if (bytesRead != bytesToRead) {
        return false;
    }
    // TODO: ensure buffer length enough
    size_t bufferPos = 0;
    count = ntohs (*((u_short*)&(buffer[bufferPos])));
    bufferPos += 2;

    sysUpTime = ntohl (*((u_long*)&(buffer[bufferPos])));
    bufferPos += 4;

    unixSeconds = ntohl (*((u_long*)&(buffer[bufferPos])));
    bufferPos += 4;

    seqNumber = ntohl (*((u_long*)&(buffer[bufferPos])));
    bufferPos += 4;

    srcId = ntohl (*((u_long*)&(buffer[bufferPos])));
    return true;
}


bool V9Packet::ParseBody()
{
    uint32_t dwRecordCount = 0;

    while (dwRecordCount < count) {
        uint32_t dwTmpRecCnt = ParseFlowSet();
        if (0 == dwTmpRecCnt) {
            break;
        }
        if (-1 == dwTmpRecCnt) {
            // TODO: signal error
            return false;
        }
        dwRecordCount += dwTmpRecCnt;

    }
    return true;
}


uint32_t V9Packet::ParseFlowSet()
{
    uint32_t dwRetVal = 0;
    uint8_t *pbBuf;

    do {
        SNFv9FlowSet soFlowSet;
        // read flowset header
        size_t stBytesRead = nfParser->m_pcoFileReader->ReadData(
            &pbBuf,
            sizeof(soFlowSet));

        if (stBytesRead != sizeof(soFlowSet)) {
            dwRetVal = -1;
            break;
        }

        soFlowSet.m_wFlowSetID = ntohs (*((u_short*)pbBuf));
        soFlowSet.m_wLength = ntohs (*((u_short*)&(pbBuf[2])));

        if (0 == soFlowSet.m_wLength) {
            dwRetVal = -1;
            break;
        }

        stBytesRead = nfParser->m_pcoFileReader->ReadData(
            &pbBuf,
            soFlowSet.m_wLength - sizeof(soFlowSet));

        if (soFlowSet.m_wLength - sizeof(soFlowSet) != stBytesRead) {
            dwRetVal = -1;
            break;
        }

        // if FlowSet contains template description
        if (soFlowSet.m_wFlowSetID <= 255) {
            switch (soFlowSet.m_wFlowSetID)
            {
            case 0:
                dwRetVal =
                    ParseTemplateFlowSet(
                        pbBuf,
                        soFlowSet.m_wLength - sizeof(soFlowSet));
                break;
            case 1:
                // record is not processed
                nfParser->m_pcoFileWriter->WriteData(
                    (uint8_t*)"Option record found\r\n",
                    21);
                dwRetVal = 1;
                nfParser->m_pcoFileWriter->Finalise();
                break;
            default:
                // record is not processed
                nfParser->m_pcoFileWriter->WriteData(
                    (uint8_t*)"Unkhown template packet\r\n",
                    25);
                nfParser->m_pcoFileWriter->Finalise();
                dwRetVal = 1;
                break;
            }

            // record is parsed correctly
        }
        // if FlowSet contains data
        else if (soFlowSet.m_wFlowSetID > 255)
        {
            uint64_t ulTmpltId = soFlowSet.m_wFlowSetID;
            ulTmpltId |= ((uint64_t)(srcId) << 32);
            auto iterTemplate = nfParser->m_mapTemplates.find (ulTmpltId);
            if (iterTemplate == nfParser->m_mapTemplates.end()) {
                // record is not processed
                // signal to calling function
                // that processed records count is wrong
                dwRetVal = 0;
            }
            else
            {
                uint32_t dwRecordCount = (soFlowSet.m_wLength - sizeof(soFlowSet))
                        / iterTemplate->second->wDataSize;
                // data parsing
                SNFv9Template *psoTemplate = iterTemplate->second;
                ParseDataFlowSet(
                    psoTemplate,
                    pbBuf,
                    dwRecordCount);
                // record processed coorectly
                dwRetVal = dwRecordCount;
            }
        }
    } while ( 0 );
    return dwRetVal;
}


int V9Packet::ParseTemplateFlowSet(uint8_t *buffer, size_t dataSize)
{
    std::map<uint64_t,SNFv9Template*>::iterator iterTemplate;
    int iRetVal = 0;
    SNFv9Template soTemplate;
    size_t stReadInd = 0;
    uint64_t ulTmpltId;

    while (stReadInd < dataSize) {
        memset(&soTemplate, 0, sizeof(soTemplate));

        // копирование Template ID
        soTemplate.wTemplateID = (buffer[stReadInd++] << 8);
        soTemplate.wTemplateID += buffer[stReadInd++];
        // копирование Field Count
        soTemplate.wFieldCount = (buffer[stReadInd++] << 8);
        soTemplate.wFieldCount = buffer[stReadInd++];

        // проверяем наличие шаблона в списке
        ulTmpltId = 0;
        ulTmpltId = soTemplate.wTemplateID;
        ulTmpltId |= ((uint64_t)(srcId) << 32);
        iterTemplate = nfParser->m_mapTemplates.find (ulTmpltId);

        // если аналогичный шаблон уже сохранен
        if (iterTemplate != nfParser->m_mapTemplates.end()) {
            // проверяем идентичность шаблонов
            // проверяем размеры данные
            if (iterTemplate->second->m_stMasterCopySize == dataSize) {
                // и идентичность данных
                if (0 == memcmp(
                    buffer,
                    iterTemplate->second->m_pmbMasterCopy,
                    dataSize)) {
                        stReadInd += sizeof(SNFv9Field) * soTemplate.wFieldCount;
                        ++ iRetVal;
                        continue;
                }
            }
            // если дошли до этого места, значит шаблоны не идентичны
            // удаляем прежний шаблон
            delete[] iterTemplate->second->m_pmbMasterCopy;
            delete iterTemplate->second;
            nfParser->m_mapTemplates.erase (iterTemplate);
        }

        // запоминаем оригинал шаблона
        soTemplate.m_stMasterCopySize = dataSize;
        soTemplate.m_pmbMasterCopy = new uint8_t[dataSize];
        memcpy(
            soTemplate.m_pmbMasterCopy,
            buffer,
            dataSize);

        SNFv9Template *psoTmpTempl;
        SNFv9Field *psoTmpField;
        psoTmpTempl = new SNFv9Template;

        *psoTmpTempl = soTemplate;

        uint32_t dwOffset = 0;

        psoTmpTempl->m_mpsoField = new SNFv9Field*[soTemplate.wFieldCount];

        for ( uint32_t i=0; i < soTemplate.wFieldCount; ++i ) {

            psoTmpField = new SNFv9Field;
            psoTmpField->m_dwOffset = dwOffset;

            psoTmpField->m_wFieldType = (buffer[stReadInd++] << 8);
            psoTmpField->m_wFieldType += buffer[stReadInd++];

            psoTmpField->m_wFieldSize =  (buffer[stReadInd++] << 8);
            psoTmpField->m_wFieldSize += buffer[stReadInd++];

            dwOffset += psoTmpField->m_wFieldSize;

            psoTmpTempl->wDataSize += psoTmpField->m_wFieldSize;

            psoTmpTempl->m_mpsoField[i] = psoTmpField;
        }

        ulTmpltId = 0;
        ulTmpltId = soTemplate.wTemplateID;
        ulTmpltId |= ((uint64_t)(srcId) << 32);

        nfParser->m_mapTemplates.insert (
            std::pair<uint64_t,SNFv9Template*>(
                ulTmpltId,
                psoTmpTempl) );
        ++ iRetVal;
        if (nfParser->m_bOutputTemplate) {
            nfParser->OutputTemplate(
                srcId,
                psoTmpTempl);
        }

    }

    return iRetVal;
}


void V9Packet::ParseDataFlowSet(
    SNFv9Template *nfTemplate,
    uint8_t *buffer,
    uint32_t recordCount)
{
    for ( uint32_t i = 0; i < recordCount; ++i )
    {
        if (nfParser->m_pcoFilter->RowFilter(
                this,
                nfTemplate,
                buffer)) {
            nfParser->OutputData(
                buffer,
                nfTemplate,
                this);
        }
        buffer += nfTemplate->wDataSize;
    }
}

void V9Packet::OutputHeader()
{
    char mcOutputBuf[1024];
    char mcTime[32];
    int iInfoSize;

    UnixTimeToStr (
        unixSeconds,
        mcTime,
        sizeof(mcTime)/sizeof(*mcTime) );

    iInfoSize = sprintf (
        mcOutputBuf,
        "Packet Header\r\n"
        "Version:\t\t%u\r\n"
        "Count:\t\t\t%u\r\n"
        "System Uptime:\t\t%u\r\n"
        "UNIX Seconds:\t\t%u (%s)\r\n"
        "Package Sequence:\t%u\r\n"
        "Source ID:\t\t%u\r\n\r\n",
        version,
        count,
        sysUpTime,
        unixSeconds,
        mcTime,
        seqNumber,
        srcId );

    nfParser->m_pcoFileWriter->WriteData(
        (uint8_t*)mcOutputBuf,
        iInfoSize);
    nfParser->m_pcoFileWriter->Finalise();
}


void V9Packet::CountStats()
{
    nfParser->m_pcoStatKeeper->CountPacket(nfParser->m_pcoFileReader->GetDir(), srcId, seqNumber);
}


