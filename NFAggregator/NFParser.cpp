#include <memory.h>
#include "NFParser.h"
#include "FileReader.h"



void CNFParser::Initialize(Aggregator *aggr)
{
    aggregator = aggr;
}

bool CNFParser::ProcessNextExportPacket(CFileReader &fileReader)
{
    uint8_t *pbBuf;
    size_t bytesRead;
    uint32_t bytesOperated = 0;
    bool retVal = true;

	do {
        bytesRead = fileReader.ReadData(
			&pbBuf,
			sizeof(NFPacket));
        if (sizeof(NFPacket) != bytesRead) {
            retVal = false;
			break;
		}

        NFPacket soNFHdr;
        bytesOperated = ParseNFHeader(
			pbBuf,
            (uint32_t)bytesRead,
			&soNFHdr);
        if (sizeof(NFPacket) != bytesOperated) {
            retVal = false;
			break;
		}

        uint32_t dwRecordCount = 0;
        uint32_t dwTmpRecCnt;

        while (dwRecordCount < soNFHdr.wCount) {
			dwTmpRecCnt = 0;
            dwTmpRecCnt = ParseFlowSet(fileReader, &soNFHdr);
			if (0 == dwTmpRecCnt) {
				break;
			}
			if (-1 == dwTmpRecCnt) {
                retVal = false;
				break;
			}
			dwRecordCount += dwTmpRecCnt;
		}
	} while( 0 );
    return retVal;
}


uint32_t CNFParser::ParseNFHeader(
    uint8_t *buffer,
    int packetLen,
    NFPacket *nfHeader)
{
    uint32_t dwRetVal = 0;
    uint32_t dwReadInd = 0, dwCopyBytes;

	do {
        if ( nullptr == buffer
            || sizeof(*nfHeader) > packetLen )
		{
			break;
		}

        dwCopyBytes = 2;
        nfHeader->wVersion = ntohs (*((u_short*)&(buffer[dwReadInd])));
        dwReadInd += dwCopyBytes;

        dwCopyBytes = 2;
        nfHeader->wCount = ntohs (*((u_short*)&(buffer[dwReadInd])));
        dwReadInd += dwCopyBytes;

        dwCopyBytes = 4;
        nfHeader->dwSysUpTime = ntohl (*((u_long*)&(buffer[dwReadInd])));
        dwReadInd += dwCopyBytes;

        dwCopyBytes = 4;
        nfHeader->dwUnixSeconds = ntohl (*((u_long*)&(buffer[dwReadInd])));
        dwReadInd += dwCopyBytes;

        dwCopyBytes = 4;
        nfHeader->dwSeqNumber = ntohl (*((u_long*)&(buffer[dwReadInd])));
        dwReadInd += dwCopyBytes;

        dwCopyBytes = 4;
        nfHeader->dwSrcId = ntohl (*((u_long*)&(buffer[dwReadInd])));
        dwReadInd += dwCopyBytes;

        if (9 != nfHeader->wVersion) {
            // TODO: signal error
			char mcMsg[256];
            size_t stMsgLen = snprintf(
				mcMsg,
                sizeof(mcMsg),
				"Error: invalid version number: %u\r\n",
                nfHeader->wVersion);
//			m_pcoFileWriter->WriteData(
//                (uint8_t*)mcMsg,
//				stMsgLen);
//			m_pcoFileWriter->Finalise();
			break;
		}

//		if (m_bCountPackets) {
//			m_pcoStatKeeper->CountPacket(
//				m_pcoFileReader->GetDir(),
//				p_psoNFv9Hdr->dwSrcId,
//				p_psoNFv9Hdr->dwSeqNumber);
//		}

		dwRetVal = dwReadInd;

	} while ( 0 );

	return dwRetVal;
}

uint32_t CNFParser::ParseFlowSet (CFileReader &fileReader, NFPacket *p_psoHeader)
{
    uint32_t dwRetVal = 0;
    uint8_t *pbBuf;

	do {
		SNFv9FlowSet soFlowSet;
        // read flowset header
        size_t stBytesRead = fileReader.ReadData(
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

        stBytesRead = fileReader.ReadData(
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
						p_psoHeader,
						pbBuf,
						soFlowSet.m_wLength - sizeof(soFlowSet));
				break;
			case 1:
                // record is not processed
//				m_pcoFileWriter->WriteData(
//                    (uint8_t*)"Option record found\r\n",
//					21);
				dwRetVal = 1;
//				m_pcoFileWriter->Finalise();
				break;
			default:
                // record is not processed
//				m_pcoFileWriter->WriteData(
//                    (uint8_t*)"Unkhown template packet\r\n",
//					25);
//				m_pcoFileWriter->Finalise();
				dwRetVal = 1;
				break;
			}

            // record is parsed correctly
		}
        // if FlowSet contains data
        else if (soFlowSet.m_wFlowSetID > 255)
		{
            uint64_t ulTmpltId = soFlowSet.m_wFlowSetID;
            ulTmpltId |= ((uint64_t)(p_psoHeader->dwSrcId) << 32);
            auto iterTemplate = m_mapTemplates.find (ulTmpltId);
			if (iterTemplate == m_mapTemplates.end()) {
                // record is not processed
                // signal to calling function
                // that processed records count is wrong
				dwRetVal = 0;
			}
			else
			{
                uint32_t dwRecordCount = (soFlowSet.m_wLength - sizeof(soFlowSet))
                        / iterTemplate->second->dataSize;
                // data parsing
                SNFv9Template *psoTemplate = iterTemplate->second;
                ParseDataFlowSet(
					p_psoHeader,
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


int CNFParser::ParseTemplateFlowSet(
    NFPacket *nfHeader,
    uint8_t *buffer,
    size_t dataSize)
{
    int iRetVal = 0;
	SNFv9Template soTemplate;
	size_t stReadInd = 0;
    uint64_t ulTmpltId;

    while (stReadInd < dataSize) {
        memset(&soTemplate, 0, sizeof(soTemplate));

        soTemplate.templateID = (buffer[stReadInd++] << 8);
        soTemplate.templateID += buffer[stReadInd++];
        soTemplate.fieldCount = (buffer[stReadInd++] << 8);
        soTemplate.fieldCount = buffer[stReadInd++];

        // check if template exists if list
		ulTmpltId = 0;
        ulTmpltId = soTemplate.templateID;
        ulTmpltId |= ((uint64_t)(nfHeader->dwSrcId) << 32);
        auto iterTemplate = m_mapTemplates.find (ulTmpltId);

        // if template with same ID is already stored
		if (iterTemplate != m_mapTemplates.end()) {
            // template found, check template identity
            if (iterTemplate->second->masterCopySize == dataSize) {
                if (0 == memcmp(
                    buffer,
                    iterTemplate->second->masterCopy,
                    dataSize)) {
                        stReadInd += sizeof(SNFv9Field) * soTemplate.fieldCount;
						++ iRetVal;
						continue;
				}
			}
            // if we came here, templates are not identical
            // remove previous template
            delete[] iterTemplate->second->masterCopy;
			delete iterTemplate->second;
			m_mapTemplates.erase (iterTemplate);
		}

        // store template master copy
        soTemplate.masterCopySize = dataSize;
        soTemplate.masterCopy = new uint8_t[dataSize];
		memcpy(
            soTemplate.masterCopy,
            buffer,
            dataSize);

        SNFv9Template *psoTmpTempl = new SNFv9Template;
		*psoTmpTempl = soTemplate;
        SNFv9Field *psoTmpField;

        uint32_t dwOffset = 0;
        psoTmpTempl->field = new SNFv9Field*[soTemplate.fieldCount];

        for ( uint32_t i=0; i < soTemplate.fieldCount; ++i ) {
			psoTmpField = new SNFv9Field;
            psoTmpField->offset = dwOffset;
            psoTmpField->fieldType = (buffer[stReadInd++] << 8);
            psoTmpField->fieldType += buffer[stReadInd++];
            psoTmpField->fieldSize =  (buffer[stReadInd++] << 8);
            psoTmpField->fieldSize += buffer[stReadInd++];
            dwOffset += psoTmpField->fieldSize;
            psoTmpTempl->dataSize += psoTmpField->fieldSize;
            psoTmpTempl->field[i] = psoTmpField;
		}

		ulTmpltId = 0;
        ulTmpltId = soTemplate.templateID;
        ulTmpltId |= ((uint64_t)(nfHeader->dwSrcId) << 32);

		m_mapTemplates.insert (
            std::pair<uint64_t,SNFv9Template*>(
				ulTmpltId,
				psoTmpTempl) );
		++ iRetVal;
	}
	return iRetVal;
}

void CNFParser::ParseDataFlowSet(
    NFPacket *nfHeader,
    SNFv9Template *nfTemplate,
    uint8_t *buffer,
    uint32_t recordCount)
{
    for (uint32_t i = 0; i < recordCount; ++i )
	{
        DataRecord* dataRecord = new DataRecord;
        memset(dataRecord, 0 ,sizeof(DataRecord));
        bool parseRes = ParseDataRecord(
                    buffer,
                    nfTemplate,
                    nfHeader,
                    dataRecord);
        if (parseRes) {
            aggregator->AddDataRecord(dataRecord);
        }
        else {
            delete dataRecord;
        }
        buffer += nfTemplate->dataSize;
	}
}


void CNFParser::CopyBlock(
    uint8_t *dest,
    size_t destSize,
    uint8_t *src,
    size_t bytesToCopy)
{
    size_t stBytesToCopy;
	size_t stWriteInd = 0;

    stBytesToCopy = bytesToCopy > destSize ?
        destSize :
        bytesToCopy;

    while ( stBytesToCopy )
	{
        -- stBytesToCopy;
        dest[stWriteInd] = src[stBytesToCopy];
		++ stWriteInd;
	}
}


bool CNFParser::ParseDataRecord(
    uint8_t *rawData,
    SNFv9Template *nfTemplate,
    NFPacket *nfHeader,
    DataRecord* dataRecord)
{
    for (size_t i = 0; i < nfTemplate->fieldCount; ++i)
	{
        switch (nfTemplate->field[i]->fieldType)
		{
		case IDS_IPV4_SRC_ADDR:
            if (!ReadInteger(rawData, nfTemplate->field[i]->fieldSize, dataRecord->srcIpAddr)) {
                return false;
            }
            break;
		case IDS_IPV4_DST_ADDR:
            if (!ReadInteger(rawData, nfTemplate->field[i]->fieldSize, dataRecord->dstIpAddr)) {
                return false;
            }
            break;
        case IDS_L4_SRC_PORT:
            if (!ReadInteger(rawData, nfTemplate->field[i]->fieldSize, dataRecord->srcPort)) {
                return false;
            }
            break;
        case IDS_L4_DST_PORT:
            if (!ReadInteger(rawData, nfTemplate->field[i]->fieldSize, dataRecord->dstPort)) {
                return false;
            }
            break;
        case IDS_IN_BYTES:
            if (!ReadInteger(rawData, nfTemplate->field[i]->fieldSize, dataRecord->inBytes)) {
                return false;
            }
            break;
        case IDS_OUT_BYTES:
            if (!ReadInteger(rawData, nfTemplate->field[i]->fieldSize, dataRecord->outBytes)) {
                return false;
            }
            break;
		case IDS_FIRST_SWITCHED:
            if (!ParseSwitchedTime(rawData, nfTemplate->field[i]->fieldSize, nfHeader, dataRecord->firstSwitched)) {
                return false;
            }
            break;
		case IDS_LAST_SWITCHED:
            if (!ParseSwitchedTime(rawData, nfTemplate->field[i]->fieldSize, nfHeader, dataRecord->lastSwitched)) {
                return false;
            }
            break;
        }
        rawData += nfTemplate->field[i]->fieldSize;
	}
    return true;
}


bool CNFParser::ParseSwitchedTime(uint8_t* rawData, int fieldSize, NFPacket* nfHeader, time_t& switchedTime)
{
    uint32_t switchedTimeMs;
    if (!ReadInteger(rawData, fieldSize, switchedTimeMs)) {
        return false;
    }

    int timeDeltaMs = switchedTimeMs - nfHeader->dwSysUpTime;
    int milliSecPart = timeDeltaMs % 1000;
    switchedTime = nfHeader->dwUnixSeconds + timeDeltaMs/1000;
    if (milliSecPart < 0) {
        switchedTime--;
    }
    return true;
}

