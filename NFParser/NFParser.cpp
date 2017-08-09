#include <memory.h>
#include "NFParser.h"
#include "FileReader.h"
#include "Filter.h"
#include "FileWriter.h"
#include "StatKeeper.h"

bool CNFParser::Init(
	CFileWriter *p_pcoFileWriter,
	CFileReader *p_pcoFileReader,
	CFilter *p_pcoFilter,
	CStatKeeper *p_pcoStatKeeper,
    uint32_t p_dwFlags)
{
    if (nullptr == p_pcoFileWriter) {
        return false;
	}
	else {
		m_pcoFileWriter = p_pcoFileWriter;
	}
    if (nullptr == p_pcoFileReader) {
        return false;
	}
	else {
		m_pcoFileReader = p_pcoFileReader;
	}
    if (nullptr == p_pcoFilter) {
        return false;
	}
	else {
		m_pcoFilter = p_pcoFilter;
	}
    if (nullptr == p_pcoStatKeeper) {
        return false;
	}
	else {
		m_pcoStatKeeper = p_pcoStatKeeper;
	}
	if (p_dwFlags & OUTPUT_NFPCKTHEADER) {
        m_bOutputHeader = true;
	}
	if (p_dwFlags & OUTPUT_NFTEMPLATE) {
        m_bOutputTemplate = true;
	}
	if (p_dwFlags & OUTPUT_USEOPT) {
        m_bUseOPT = true;
        strncpy (m_msoOPT[0].m_mcFieldName, "First Time", sizeof(m_msoOPT[0].m_mcFieldName));
        strncpy (m_msoOPT[1].m_mcFieldName, "Last Time", sizeof(m_msoOPT[1].m_mcFieldName));
        strncpy (m_msoOPT[2].m_mcFieldName, "Src IP", sizeof(m_msoOPT[2].m_mcFieldName));
        strncpy (m_msoOPT[3].m_mcFieldName, "Src Port", sizeof(m_msoOPT[3].m_mcFieldName));
        strncpy (m_msoOPT[4].m_mcFieldName, "Dst IP", sizeof(m_msoOPT[4].m_mcFieldName));
        strncpy (m_msoOPT[5].m_mcFieldName, "Dst Port", sizeof(m_msoOPT[5].m_mcFieldName));
        strncpy (m_msoOPT[6].m_mcFieldName, "Bytes", sizeof(m_msoOPT[6].m_mcFieldName));
		m_mapOPT.insert (std::make_pair(22, 0));	// First Time
		m_mapOPT.insert (std::make_pair(21, 1));	// Last Time
		m_mapOPT.insert (std::make_pair(8, 2));		// Src IP
		m_mapOPT.insert (std::make_pair(7, 3));		// Src Port
		m_mapOPT.insert (std::make_pair(12, 4));	// Dst IP
		m_mapOPT.insert (std::make_pair(11, 5));	// Dst Port
        m_mapOPT.insert (std::make_pair(1, 6));		// uint8_ts
		for (int iInd = 0; iInd < sizeof(m_msoOPT)/sizeof(*m_msoOPT); ++iInd) {
			if (iInd) {
                m_pcoFileWriter->WriteData ((uint8_t*)"\t", 1);
			}
            m_pcoFileWriter->WriteData ((uint8_t*)m_msoOPT[iInd].m_mcFieldName, strlen (m_msoOPT[iInd].m_mcFieldName));
		}
        m_pcoFileWriter->WriteData ((uint8_t*)"\r\n", 2);
	}
	if (p_dwFlags & OUTPUT_DOD) {
        m_bDontOutputData = true;
	}

    return true;
}

bool CNFParser::ReadNFPacket()
{
    bool bRetVal = true;
    uint8_t *pbBuf;
    size_t stuint8_tsRead;
    uint32_t dwuint8_tsOperated = 0;

	do {

        if (nullptr == m_pcoFileReader) {
            bRetVal = false;
			break;
		}

        stuint8_tsRead = m_pcoFileReader->ReadData(
			&pbBuf,
			sizeof(SNFv9Header));

        if (sizeof(SNFv9Header) != stuint8_tsRead) {
            bRetVal = false;
			break;
		}

		SNFv9Header soNFHdr;

        dwuint8_tsOperated = ParseNFHeader(
			pbBuf,
            (uint32_t)stuint8_tsRead,
			&soNFHdr);

        if (sizeof(SNFv9Header) != dwuint8_tsOperated) {
            bRetVal = false;
			break;
		}

		if (m_bOutputHeader) {
			OutputHeader (&soNFHdr);
		}

        uint32_t dwRecordCount;
        uint32_t dwTmpRecCnt;

		dwRecordCount = 0;

		while (dwRecordCount < soNFHdr.wCount) {

			dwTmpRecCnt = 0;

			dwTmpRecCnt = ParseFlowSet (&soNFHdr);

			if (0 == dwTmpRecCnt) {
				break;
			}

			if (-1 == dwTmpRecCnt) {
                bRetVal = false;
				break;
			}

			dwRecordCount += dwTmpRecCnt;

		}

	} while( 0 );

	return bRetVal;
}

CNFParser::CNFParser (bool p_bCountPackets)
{
    m_pcoFileWriter = nullptr;
    m_pcoFileReader = nullptr;
    m_pcoFilter = nullptr;
    m_pcoStatKeeper = nullptr;
    m_bOutputHeader = false;
    m_bOutputTemplate = false;
	memset(m_msoOPT, 0, sizeof(m_msoOPT));
    m_bUseOPT = false;
	m_bCountPackets = p_bCountPackets;
    m_bDontOutputData = false;
}

CNFParser::~CNFParser(void)
{
}

uint32_t CNFParser::ParseNFHeader(
    uint8_t *p_pmbBuf,
	int p_iPackLen,
	SNFv9Header *p_psoNFv9Hdr)
{
    uint32_t dwRetVal = 0;
    uint32_t dwReadInd = 0,
        dwCopyuint8_ts;

	do {
        if ( nullptr == p_pmbBuf
			|| sizeof(*p_psoNFv9Hdr) > p_iPackLen )
		{
			break;
		}

		// копирование версии NetFlow
        dwCopyuint8_ts = 2;
		p_psoNFv9Hdr->wVersion = ntohs (*((u_short*)&(p_pmbBuf[dwReadInd])));
        dwReadInd += dwCopyuint8_ts;

		// копирование Count
        dwCopyuint8_ts = 2;
		p_psoNFv9Hdr->wCount = ntohs (*((u_short*)&(p_pmbBuf[dwReadInd])));
        dwReadInd += dwCopyuint8_ts;

		// копирование System Uptime
        dwCopyuint8_ts = 4;
		p_psoNFv9Hdr->dwSysUpTime = ntohl (*((u_long*)&(p_pmbBuf[dwReadInd])));
        dwReadInd += dwCopyuint8_ts;

		// копирование Unix Seconds
        dwCopyuint8_ts = 4;
		p_psoNFv9Hdr->dwUnixSeconds = ntohl (*((u_long*)&(p_pmbBuf[dwReadInd])));
        dwReadInd += dwCopyuint8_ts;

		// копирование Package Sequence
        dwCopyuint8_ts = 4;
		p_psoNFv9Hdr->dwSeqNumber = ntohl (*((u_long*)&(p_pmbBuf[dwReadInd])));
        dwReadInd += dwCopyuint8_ts;

		// копирование Source ID
        dwCopyuint8_ts = 4;
		p_psoNFv9Hdr->dwSrcId = ntohl (*((u_long*)&(p_pmbBuf[dwReadInd])));
        dwReadInd += dwCopyuint8_ts;

		if (9 != p_psoNFv9Hdr->wVersion) {
			char mcMsg[256];
			size_t stMsgLen;

            stMsgLen = snprintf(
				mcMsg,
                sizeof(mcMsg),
				"Error: invalid version number: %u\r\n",
				p_psoNFv9Hdr->wVersion);
			m_pcoFileWriter->WriteData(
                (uint8_t*)mcMsg,
				stMsgLen);
			m_pcoFileWriter->Finalise();
			break;
		}

		if (m_bCountPackets) {
			m_pcoStatKeeper->CountPacket(
				m_pcoFileReader->GetDir(),
				p_psoNFv9Hdr->dwSrcId,
				p_psoNFv9Hdr->dwSeqNumber);
		}

		dwRetVal = dwReadInd;

	} while ( 0 );

	return dwRetVal;
}

uint32_t CNFParser::ParseFlowSet (SNFv9Header *p_psoHeader)
{
    uint32_t dwRetVal = 0;
    uint8_t *pbBuf;
    size_t stuint8_tRead;

	do {

		SNFv9FlowSet soFlowSet;

		// считываем из файла заголовок FlowSet
        stuint8_tRead = m_pcoFileReader->ReadData(
			&pbBuf,
			sizeof(soFlowSet));

        if (stuint8_tRead != sizeof(soFlowSet)) {
			dwRetVal = -1;
			break;
		}

		// копирование FlowSet ID
		soFlowSet.m_wFlowSetID = ntohs (*((u_short*)pbBuf));

		// копирование Length
		soFlowSet.m_wLength = ntohs (*((u_short*)&(pbBuf[2])));

		if (0 == soFlowSet.m_wLength) {
			dwRetVal = -1;
			break;
		}

		// считываем из файла данные
        stuint8_tRead = m_pcoFileReader->ReadData(
			&pbBuf,
			soFlowSet.m_wLength - sizeof(soFlowSet));

        if (soFlowSet.m_wLength - sizeof(soFlowSet) != stuint8_tRead) {
			dwRetVal = -1;
			break;
		}

		// если FlowSet содержит описание шаблона
		if (255 >= soFlowSet.m_wFlowSetID) {
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
				// запись не обработана
				m_pcoFileWriter->WriteData(
                    (uint8_t*)"Option record found\r\n",
					21);
				dwRetVal = 1;
				m_pcoFileWriter->Finalise();
				break;
			default:
				// запись не обработана
				m_pcoFileWriter->WriteData(
                    (uint8_t*)"Unkhown template packet\r\n",
					25);
				m_pcoFileWriter->Finalise();
				dwRetVal = 1;
				break;
			}

			// запись обработана корректно
		}
		// если FlowSet содержит данные
		else if ( 255 < soFlowSet.m_wFlowSetID )
		{
            uint64_t ulTmpltId;
            std::map<uint64_t,SNFv9Template*>::iterator iterTemplate;

			ulTmpltId = 0;
			ulTmpltId = soFlowSet.m_wFlowSetID;
            ulTmpltId |= ((uint64_t)(p_psoHeader->dwSrcId) << 32);
			iterTemplate = m_mapTemplates.find (ulTmpltId);

			if (iterTemplate == m_mapTemplates.end()) {
				// запись не обработана
				// сигнализируем вызывающей функции,
				// что количество обработанных записей некорректно
				dwRetVal = 0;
			}
			else
			{
                uint32_t dwRecourdCount;

				dwRecourdCount = (soFlowSet.m_wLength - sizeof(soFlowSet)) / iterTemplate->second->wDataSize;

				// парсинг данных
				///////////////////////////////////////////////////////////
				SNFv9Template *psoTemplate;

				psoTemplate = iterTemplate->second;

				ParseDataFlowSet(
					p_psoHeader,
					psoTemplate,
					pbBuf,
					dwRecourdCount);
				///////////////////////////////////////////////////////////

				// запись обработана корректно
				dwRetVal = dwRecourdCount;

			}
		}

	} while ( 0 );

	return dwRetVal;
}

int CNFParser::ParseTemplateFlowSet(
	SNFv9Header *p_psoHeader,
    uint8_t *p_pmbBuf,
	size_t p_stDataSize)
{
    std::map<uint64_t,SNFv9Template*>::iterator iterTemplate;
	int iRetVal = 0;
	SNFv9Template soTemplate;
	size_t stReadInd = 0;
    uint64_t ulTmpltId;

	while (stReadInd < p_stDataSize) {
        memset(&soTemplate, 0, sizeof(soTemplate));

		// копирование Template ID
		soTemplate.wTemplateID = (p_pmbBuf[stReadInd++] << 8);
		soTemplate.wTemplateID += p_pmbBuf[stReadInd++];
		// копирование Field Count
		soTemplate.wFieldCount = (p_pmbBuf[stReadInd++] << 8);
		soTemplate.wFieldCount = p_pmbBuf[stReadInd++];

		// проверяем наличие шаблона в списке
		ulTmpltId = 0;
		ulTmpltId = soTemplate.wTemplateID;
        ulTmpltId |= ((uint64_t)(p_psoHeader->dwSrcId) << 32);
		iterTemplate = m_mapTemplates.find (ulTmpltId);

		// если аналогичный шаблон уже сохранен
		if (iterTemplate != m_mapTemplates.end()) {
			// проверяем идентичность шаблонов
			// проверяем размеры данные
			if (iterTemplate->second->m_stMasterCopySize == p_stDataSize) {
				// и идентичность данных
				if (0 == memcmp(
					p_pmbBuf,
					iterTemplate->second->m_pmbMasterCopy,
					p_stDataSize)) {
						stReadInd += sizeof(SNFv9Field) * soTemplate.wFieldCount;
						++ iRetVal;
						continue;
				}
			}
			// если дошли до этого места, значит шаблоны не идентичны
			// удаляем прежний шаблон
			delete[] iterTemplate->second->m_pmbMasterCopy;
			delete iterTemplate->second;
			m_mapTemplates.erase (iterTemplate);
		}

		// запоминаем оригинал шаблона
		soTemplate.m_stMasterCopySize = p_stDataSize;
        soTemplate.m_pmbMasterCopy = new uint8_t[p_stDataSize];
		memcpy(
			soTemplate.m_pmbMasterCopy,
			p_pmbBuf,
			p_stDataSize);

		SNFv9Template *psoTmpTempl;
		SNFv9Field *psoTmpField;
		psoTmpTempl = new SNFv9Template;

		*psoTmpTempl = soTemplate;

        uint32_t dwOffset = 0;

		psoTmpTempl->m_mpsoField = new SNFv9Field*[soTemplate.wFieldCount];

        for ( uint32_t i=0; i < soTemplate.wFieldCount; ++i ) {

			psoTmpField = new SNFv9Field;
			psoTmpField->m_dwOffset = dwOffset;

			psoTmpField->m_wFieldType = (p_pmbBuf[stReadInd++] << 8);
			psoTmpField->m_wFieldType += p_pmbBuf[stReadInd++];

			psoTmpField->m_wFieldSize =  (p_pmbBuf[stReadInd++] << 8);
			psoTmpField->m_wFieldSize += p_pmbBuf[stReadInd++];

			dwOffset += psoTmpField->m_wFieldSize;

			psoTmpTempl->wDataSize += psoTmpField->m_wFieldSize;

			psoTmpTempl->m_mpsoField[i] = psoTmpField;
		}

		ulTmpltId = 0;
		ulTmpltId = soTemplate.wTemplateID;
        ulTmpltId |= ((uint64_t)(p_psoHeader->dwSrcId) << 32);

		m_mapTemplates.insert (
            std::pair<uint64_t,SNFv9Template*>(
				ulTmpltId,
				psoTmpTempl) );
		++ iRetVal;
		if (m_bOutputTemplate) {
			OutputTemplate(
				p_psoHeader->dwSrcId,
				psoTmpTempl);
		}

	}

	return iRetVal;
}

void CNFParser::ParseDataFlowSet(
	SNFv9Header *p_psoHeader,
	SNFv9Template *p_psoTemplate,
    uint8_t *p_pmbBuf,
    uint32_t p_dwRecordCount)
{
	//
	// обходим все записи

    for ( uint32_t i = 0; i < p_dwRecordCount; ++i )
	{
		if (m_pcoFilter->RowFilter(
				p_psoHeader,
				p_psoTemplate,
				p_pmbBuf)) {
			OutputData(
				p_pmbBuf,
				p_psoTemplate,
				p_psoHeader);
		}
		p_pmbBuf += p_psoTemplate->wDataSize;
	}
}

void CNFParser::UnixTimeToStr(
    uint32_t p_dwUnixTime,
	char *m_pmcOutputStr,
	size_t p_stMaxChars)
{
	time_t ttTime;
	tm soTime;

	ttTime = (time_t) p_dwUnixTime;

    gmtime_r ( &ttTime, &soTime );

	strftime (
		m_pmcOutputStr,
		p_stMaxChars,
		"%d.%m.%Y %H:%M:%S",
		&soTime );
}

void CNFParser::CopyBlock(
    uint8_t *p_pmbDst,
	size_t p_stDstSize,
    uint8_t *p_pmbSrc,
    size_t p_stuint8_tsToCopy)
{
    size_t stuint8_tsToCopy;
	size_t stWriteInd = 0;

    stuint8_tsToCopy = p_stuint8_tsToCopy > p_stDstSize ?
		p_stDstSize :
        p_stuint8_tsToCopy;

    while ( stuint8_tsToCopy )
	{
        -- stuint8_tsToCopy;
        p_pmbDst[stWriteInd] = p_pmbSrc[stuint8_tsToCopy];
		++ stWriteInd;
	}
}

void CNFParser::OutputHeader (SNFv9Header *p_psoHeader)
{
	char mcOutputBuf[1024];
	char mcTime[32];
	int iInfoSize;

	UnixTimeToStr (
		p_psoHeader->dwUnixSeconds,
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
		p_psoHeader->wVersion,
		p_psoHeader->wCount,
		p_psoHeader->dwSysUpTime,
		p_psoHeader->dwUnixSeconds,
		mcTime,
		p_psoHeader->dwSeqNumber,
		p_psoHeader->dwSrcId );

	m_pcoFileWriter->WriteData(
        (uint8_t*)mcOutputBuf,
		iInfoSize);
	m_pcoFileWriter->Finalise();
}

void CNFParser::OutputTemplate(
    uint32_t p_dwSrcId,
	SNFv9Template *p_psoTemplate)
{
	char mcFieldName[256];
	char mcOutputData[1024];
	int iDataLen;

    iDataLen = snprintf (
		mcOutputData,
        sizeof(mcOutputData),
		"Source ID: \t%d\r\n"
		"Template ID: \t%d\r\n"
		"Field Count:\t%d\r\n"
		"Field ID\tField Size\tField Name\r\n",
		p_dwSrcId,
		p_psoTemplate->wTemplateID,
		p_psoTemplate->wFieldCount );

	m_pcoFileWriter->WriteData(
        (uint8_t*)mcOutputData,
		iDataLen);

    for ( unsigned int uiI = 0; uiI < p_psoTemplate->wFieldCount; ++uiI )
	{
        iDataLen = 0; //LoadStringA (
//            nullptr,
//			p_psoTemplate->m_mpsoField[uiI]->m_wFieldType,
//			mcFieldName,
//			sizeof(mcFieldName));


        if ( 0 == iDataLen )
        {
            iDataLen = snprintf (
                mcFieldName,
                sizeof(mcFieldName),
                "%s",
                "Unknown Field" );
        }

        iDataLen = snprintf (
			mcOutputData,
            sizeof(mcOutputData),
			"%d\t%d\t%s\r\n",
			p_psoTemplate->m_mpsoField[uiI]->m_wFieldType,
			p_psoTemplate->m_mpsoField[uiI]->m_wFieldSize,
			mcFieldName );

		m_pcoFileWriter->WriteData(
            (uint8_t*)mcOutputData,
			iDataLen);
	}

	m_pcoFileWriter->WriteData(
        (uint8_t*)"\r\n",
		2);
}

void CNFParser::OutputData(
    uint8_t *p_pmbBuf,
	SNFv9Template *p_psoTemplate,
	SNFv9Header *p_psoHeader)
{
    uint8_t mbValue[256];
	char mcValue[256];
	int iDataLen;
    std::map<uint32_t,uint32_t>::iterator iterOPT;

    for (uint16_t uiI = 0; uiI < p_psoTemplate->wFieldCount; ++uiI)
	{
		if (m_bUseOPT) {
			iterOPT = m_mapOPT.find (p_psoTemplate->m_mpsoField[uiI]->m_wFieldType);
			if (iterOPT == m_mapOPT.end()) {
				p_pmbBuf += p_psoTemplate->m_mpsoField[uiI]->m_wFieldSize;
				continue;
			}
		}
        memset(mbValue, 0, sizeof(mbValue));
		/*	Переставляем байты, если необходимо
		 */
		switch (p_psoTemplate->m_mpsoField[uiI]->m_wFieldSize) {
		case 1:
			break;
		case 2:
			*((u_short*)(mbValue)) = ntohs (*(u_short*)p_pmbBuf);
			break;
		case 4:
			*((u_long*)(mbValue)) = ntohl (*(u_long*)p_pmbBuf);
			break;
		default:
			CopyBlock(
				mbValue,
				sizeof(mbValue),
				p_pmbBuf,
				p_psoTemplate->m_mpsoField[uiI]->m_wFieldSize);
			break;
		}

		switch (p_psoTemplate->m_mpsoField[uiI]->m_wFieldType)
		{
		case IDS_IPV4_SRC_ADDR:
		case IDS_IPV4_DST_ADDR:
            iDataLen = snprintf (
				mcValue,
				sizeof(mcValue)/sizeof(*mcValue),
				"%u.%u.%u.%u",
                ((*((uint32_t*)(mbValue))) & 0xFF000000) >> 24,
                ((*((uint32_t*)(mbValue))) & 0x00FF0000) >> 16,
                ((*((uint32_t*)(mbValue))) & 0x0000FF00) >> 8,
                ((*((uint32_t*)(mbValue))) & 0x000000FF) );
			break;
		case IDS_FIRST_SWITCHED:
		case IDS_LAST_SWITCHED:
			{
                uint32_t dwUnixSec;
				int iTimeDelta;
				int iMilliSec;
				char mcUnixTime[32];

				// вычисляем на сколько время формирования пакета NetFlow
				// больше времени прохождения потока
                iTimeDelta = *((uint32_t*)(mbValue)) - p_psoHeader->dwSysUpTime;

				// определяем кличество тысячных долей секунды
				iMilliSec = iTimeDelta % 1000;

				// определяем время прохождения потока
				dwUnixSec = p_psoHeader->dwUnixSeconds + iTimeDelta/1000;

				if ( iMilliSec < 0 )
				{
					--dwUnixSec;
					iMilliSec += 1000;
				}

				UnixTimeToStr (
					dwUnixSec,
					mcUnixTime,
					sizeof(mcUnixTime)/sizeof(*mcUnixTime) );

                iDataLen = sprintf(
					mcValue,
					"%s,%03d",
					mcUnixTime,
					iMilliSec );
			}
			break;
		default:
            if (IDS_OUT_BYTES == p_psoTemplate->m_mpsoField[uiI]->m_wFieldType
                || IDS_IN_BYTES == p_psoTemplate->m_mpsoField[uiI]->m_wFieldType) {
                    m_pcoStatKeeper->CountOctets (*((uint32_t*)(mbValue)));
			}
            uint32_t dwValue = *((uint32_t*)(mbValue));
			switch (p_psoTemplate->m_mpsoField[uiI]->m_wFieldSize) {
			case 1: dwValue = 0x000000FF & dwValue; break;
			case 2: dwValue = 0x0000FFFF & dwValue; break;
			}
            iDataLen = snprintf(
				mcValue,
                sizeof(mcValue),
				"%u",
				dwValue);
		}

		if (m_bUseOPT) {
            strncpy (m_msoOPT[iterOPT->second].m_mcValue, mcValue,
                    sizeof(m_msoOPT[iterOPT->second].m_mcValue));
			m_msoOPT[iterOPT->second].m_iDataSize = iDataLen;
		}
		else {
			if (! m_bDontOutputData) {
				m_pcoFileWriter->WriteData(
                    (uint8_t*)mcValue,
					iDataLen);

				if (uiI + 1 < p_psoTemplate->wFieldCount) {
					m_pcoFileWriter->WriteData(
                        (uint8_t*)"\t",
						1);
				}
			}
		}
		p_pmbBuf += p_psoTemplate->m_mpsoField[uiI]->m_wFieldSize;
	}

	if (m_bUseOPT && ! m_bDontOutputData) {
		for (int iInd = 0; iInd < sizeof(m_msoOPT)/sizeof(*m_msoOPT); ++iInd) {
			if (iInd) {
				m_pcoFileWriter->WriteData(
                    (uint8_t*)"\t",
					1);
			}
			m_pcoFileWriter->WriteData(
                (uint8_t*)m_msoOPT[iInd].m_mcValue,
				m_msoOPT[iInd].m_iDataSize);
			m_msoOPT[iInd].m_mcValue[0] = '\0';
			m_msoOPT[iInd].m_iDataSize = 0;
		}
	}

	if (! m_bDontOutputData) {
		m_pcoFileWriter->WriteData(
            (uint8_t*)"\r\n",
			2);
	}
}
