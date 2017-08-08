#include "NFParser.h"
#include "FileReader.h"
#include "Filter.h"
#include "FileWriter.h"
#include "StatKeeper.h"

BOOL CNFParser::Init(
	CFileWriter *p_pcoFileWriter,
	CFileReader *p_pcoFileReader,
	CFilter *p_pcoFilter,
	CStatKeeper *p_pcoStatKeeper,
	DWORD p_dwFlags)
{
	if (NULL == p_pcoFileWriter) {
		return FALSE;
	}
	else {
		m_pcoFileWriter = p_pcoFileWriter;
	}
	if (NULL == p_pcoFileReader) {
		return FALSE;
	}
	else {
		m_pcoFileReader = p_pcoFileReader;
	}
	if (NULL == p_pcoFilter) {
		return FALSE;
	}
	else {
		m_pcoFilter = p_pcoFilter;
	}
	if (NULL == p_pcoStatKeeper) {
		return FALSE;
	}
	else {
		m_pcoStatKeeper = p_pcoStatKeeper;
	}
	if (p_dwFlags & OUTPUT_NFPCKTHEADER) {
		m_bOutputHeader = TRUE;
	}
	if (p_dwFlags & OUTPUT_NFTEMPLATE) {
		m_bOutputTemplate = TRUE;
	}
	if (p_dwFlags & OUTPUT_USEOPT) {
		m_bUseOPT = TRUE;
		strcpy_s (m_msoOPT[0].m_mcFieldName, sizeof(m_msoOPT[0].m_mcFieldName), "First Time");
		strcpy_s (m_msoOPT[1].m_mcFieldName, sizeof(m_msoOPT[1].m_mcFieldName), "Last Time");
		strcpy_s (m_msoOPT[2].m_mcFieldName, sizeof(m_msoOPT[2].m_mcFieldName), "Src IP");
		strcpy_s (m_msoOPT[3].m_mcFieldName, sizeof(m_msoOPT[3].m_mcFieldName), "Src Port");
		strcpy_s (m_msoOPT[4].m_mcFieldName, sizeof(m_msoOPT[4].m_mcFieldName), "Dst IP");
		strcpy_s (m_msoOPT[5].m_mcFieldName, sizeof(m_msoOPT[5].m_mcFieldName), "Dst Port");
		strcpy_s (m_msoOPT[6].m_mcFieldName, sizeof(m_msoOPT[6].m_mcFieldName), "Bytes");
		m_mapOPT.insert (std::make_pair(22, 0));	// First Time
		m_mapOPT.insert (std::make_pair(21, 1));	// Last Time
		m_mapOPT.insert (std::make_pair(8, 2));		// Src IP
		m_mapOPT.insert (std::make_pair(7, 3));		// Src Port
		m_mapOPT.insert (std::make_pair(12, 4));	// Dst IP
		m_mapOPT.insert (std::make_pair(11, 5));	// Dst Port
		m_mapOPT.insert (std::make_pair(1, 6));		// Bytes
		for (int iInd = 0; iInd < sizeof(m_msoOPT)/sizeof(*m_msoOPT); ++iInd) {
			if (iInd) {
				m_pcoFileWriter->WriteData ((BYTE*)"\t", 1);
			}
			m_pcoFileWriter->WriteData ((BYTE*)m_msoOPT[iInd].m_mcFieldName, strlen (m_msoOPT[iInd].m_mcFieldName));
		}
		m_pcoFileWriter->WriteData ((BYTE*)"\r\n", 2);
	}
	if (p_dwFlags & OUTPUT_DOD) {
		m_bDontOutputData = TRUE;
	}

	return TRUE;
}

BOOL CNFParser::ReadNFPacket()
{
	BOOL bRetVal = TRUE;
	BYTE *pbBuf;
	size_t stBytesRead;
	DWORD dwBytesOperated = 0;

	do {

		if (NULL == m_pcoFileReader) {
			bRetVal = FALSE;
			break;
		}

		stBytesRead = m_pcoFileReader->ReadData(
			&pbBuf,
			sizeof(SNFv9Header));

		if (sizeof(SNFv9Header) != stBytesRead) {
			bRetVal = FALSE;
			break;
		}

		SNFv9Header soNFHdr;

		dwBytesOperated = ParseNFHeader(
			pbBuf,
			(DWORD)stBytesRead,
			&soNFHdr);

		if (sizeof(SNFv9Header) != dwBytesOperated) {
			bRetVal = FALSE;
			break;
		}

		if (m_bOutputHeader) {
			OutputHeader (&soNFHdr);
		}

		DWORD dwRecordCount;
		DWORD dwTmpRecCnt;

		dwRecordCount = 0;

		while (dwRecordCount < soNFHdr.wCount) {

			dwTmpRecCnt = 0;

			dwTmpRecCnt = ParseFlowSet (&soNFHdr);

			if (0 == dwTmpRecCnt) {
				break;
			}

			if (-1 == dwTmpRecCnt) {
				bRetVal = FALSE;
				break;
			}

			dwRecordCount += dwTmpRecCnt;

		}

	} while( 0 );

	return bRetVal;
}

CNFParser::CNFParser (BOOL p_bCountPackets)
{
	m_pcoFileWriter = NULL;
	m_pcoFileReader = NULL;
	m_pcoFilter = NULL;
	m_pcoStatKeeper = NULL;
	m_bOutputHeader = FALSE;
	m_bOutputTemplate = FALSE;
	memset(m_msoOPT, 0, sizeof(m_msoOPT));
	m_bUseOPT = FALSE;
	m_bCountPackets = p_bCountPackets;
	m_bDontOutputData = FALSE;
}

CNFParser::~CNFParser(void)
{
}

DWORD CNFParser::ParseNFHeader(
	BYTE *p_pmbBuf,
	int p_iPackLen,
	SNFv9Header *p_psoNFv9Hdr)
{
	DWORD dwRetVal = 0;
	DWORD dwReadInd = 0,
		dwCopyBytes;

	do {
		if ( NULL == p_pmbBuf
			|| sizeof(*p_psoNFv9Hdr) > p_iPackLen )
		{
			break;
		}

		// копирование версии NetFlow
		dwCopyBytes = 2;
		p_psoNFv9Hdr->wVersion = ntohs (*((u_short*)&(p_pmbBuf[dwReadInd])));
		dwReadInd += dwCopyBytes;

		// копирование Count
		dwCopyBytes = 2;
		p_psoNFv9Hdr->wCount = ntohs (*((u_short*)&(p_pmbBuf[dwReadInd])));
		dwReadInd += dwCopyBytes;

		// копирование System Uptime
		dwCopyBytes = 4;
		p_psoNFv9Hdr->dwSysUpTime = ntohl (*((u_long*)&(p_pmbBuf[dwReadInd])));
		dwReadInd += dwCopyBytes;

		// копирование Unix Seconds
		dwCopyBytes = 4;
		p_psoNFv9Hdr->dwUnixSeconds = ntohl (*((u_long*)&(p_pmbBuf[dwReadInd])));
		dwReadInd += dwCopyBytes;

		// копирование Package Sequence
		dwCopyBytes = 4;
		p_psoNFv9Hdr->dwSeqNumber = ntohl (*((u_long*)&(p_pmbBuf[dwReadInd])));
		dwReadInd += dwCopyBytes;

		// копирование Source ID
		dwCopyBytes = 4;
		p_psoNFv9Hdr->dwSrcId = ntohl (*((u_long*)&(p_pmbBuf[dwReadInd])));
		dwReadInd += dwCopyBytes;

		if (9 != p_psoNFv9Hdr->wVersion) {
			char mcMsg[256];
			size_t stMsgLen;

			stMsgLen = sprintf_s(
				mcMsg,
				sizeof(mcMsg)/sizeof(*mcMsg),
				"Error: invalid version number: %u\r\n",
				p_psoNFv9Hdr->wVersion);
			m_pcoFileWriter->WriteData(
				(BYTE*)mcMsg,
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

DWORD CNFParser::ParseFlowSet (SNFv9Header *p_psoHeader)
{
	DWORD dwRetVal = 0;
	BYTE *pbBuf;
	size_t stByteRead;

	do {

		SNFv9FlowSet soFlowSet;

		// считываем из файла заголовок FlowSet
		stByteRead = m_pcoFileReader->ReadData(
			&pbBuf,
			sizeof(soFlowSet));

		if (stByteRead != sizeof(soFlowSet)) {
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
		stByteRead = m_pcoFileReader->ReadData(
			&pbBuf,
			soFlowSet.m_wLength - sizeof(soFlowSet));

		if (soFlowSet.m_wLength - sizeof(soFlowSet) != stByteRead) {
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
					(BYTE*)"Option record found\r\n",
					21);
				dwRetVal = 1;
				m_pcoFileWriter->Finalise();
				break;
			default:
				// запись не обработана
				m_pcoFileWriter->WriteData(
					(BYTE*)"Unkhown template packet\r\n",
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
			ULONGLONG ulTmpltId;
			std::map<ULONGLONG,SNFv9Template*>::iterator iterTemplate;

			ulTmpltId = 0;
			ulTmpltId = soFlowSet.m_wFlowSetID;
			ulTmpltId |= ((ULONGLONG)(p_psoHeader->dwSrcId) << 32);
			iterTemplate = m_mapTemplates.find (ulTmpltId);

			if (iterTemplate == m_mapTemplates.end()) {
				// запись не обработана
				// сигнализируем вызывающей функции,
				// что количество обработанных записей некорректно
				dwRetVal = 0;
			}
			else
			{
				DWORD dwRecourdCount;

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
	BYTE *p_pmbBuf,
	size_t p_stDataSize)
{
	std::map<ULONGLONG,SNFv9Template*>::iterator iterTemplate;
	int iRetVal = 0;
	SNFv9Template soTemplate;
	size_t stReadInd = 0;
	ULONGLONG ulTmpltId;

	while (stReadInd < p_stDataSize) {

		// инициализация структуры
		ZeroMemory(
			&soTemplate,
			sizeof(soTemplate));

		// копирование Template ID
		soTemplate.wTemplateID = (p_pmbBuf[stReadInd++] << 8);
		soTemplate.wTemplateID += p_pmbBuf[stReadInd++];
		// копирование Field Count
		soTemplate.wFieldCount = (p_pmbBuf[stReadInd++] << 8);
		soTemplate.wFieldCount = p_pmbBuf[stReadInd++];

		// проверяем наличие шаблона в списке
		ulTmpltId = 0;
		ulTmpltId = soTemplate.wTemplateID;
		ulTmpltId |= ((ULONGLONG)(p_psoHeader->dwSrcId) << 32);
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
		soTemplate.m_pmbMasterCopy = new BYTE[p_stDataSize];
		memcpy(
			soTemplate.m_pmbMasterCopy,
			p_pmbBuf,
			p_stDataSize);

		SNFv9Template *psoTmpTempl;
		SNFv9Field *psoTmpField;
		psoTmpTempl = new SNFv9Template;

		*psoTmpTempl = soTemplate;

		DWORD dwOffset = 0;

		psoTmpTempl->m_mpsoField = new SNFv9Field*[soTemplate.wFieldCount];

		for ( DWORD i=0; i < soTemplate.wFieldCount; ++i ) {

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
		ulTmpltId |= ((ULONGLONG)(p_psoHeader->dwSrcId) << 32);

		m_mapTemplates.insert (
			std::pair<ULONGLONG,SNFv9Template*>(
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
	BYTE *p_pmbBuf,
	DWORD p_dwRecordCount)
{
	//
	// обходим все записи

	for ( DWORD i = 0; i < p_dwRecordCount; ++i )
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
	DWORD p_dwUnixTime,
	char *m_pmcOutputStr,
	size_t p_stMaxChars)
{
	time_t ttTime;
	tm soTime;

	ttTime = (time_t) p_dwUnixTime;

	gmtime_s ( &soTime, &ttTime );

	strftime (
		m_pmcOutputStr,
		p_stMaxChars,
		"%d.%m.%Y %H:%M:%S",
		&soTime );
}

void CNFParser::CopyBlock(
	BYTE *p_pmbDst,
	size_t p_stDstSize,
	BYTE *p_pmbSrc,
	size_t p_stBytesToCopy)
{
	size_t stBytesToCopy;
	size_t stWriteInd = 0;

	stBytesToCopy = p_stBytesToCopy > p_stDstSize ?
		p_stDstSize :
		p_stBytesToCopy;

	while ( stBytesToCopy )
	{
		-- stBytesToCopy;
		p_pmbDst[stWriteInd] = p_pmbSrc[stBytesToCopy];
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

	iInfoSize = sprintf_s (
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
		(BYTE*)mcOutputBuf,
		iInfoSize);
	m_pcoFileWriter->Finalise();
}

void CNFParser::OutputTemplate(
	DWORD p_dwSrcId,
	SNFv9Template *p_psoTemplate)
{
	char mcFieldName[256];
	char mcOutputData[1024];
	int iDataLen;

	iDataLen = sprintf_s (
		mcOutputData,
		sizeof(mcOutputData)/sizeof(*mcOutputData),
		"Source ID: \t%d\r\n"
		"Template ID: \t%d\r\n"
		"Field Count:\t%d\r\n"
		"Field ID\tField Size\tField Name\r\n",
		p_dwSrcId,
		p_psoTemplate->wTemplateID,
		p_psoTemplate->wFieldCount );

	m_pcoFileWriter->WriteData(
		(BYTE*)mcOutputData,
		iDataLen);

	for ( UINT uiI = 0; uiI < p_psoTemplate->wFieldCount; ++uiI )
	{
		iDataLen = LoadStringA (
			NULL,
			p_psoTemplate->m_mpsoField[uiI]->m_wFieldType,
			mcFieldName,
			sizeof(mcFieldName)/sizeof(*mcFieldName) );

		if ( 0 == iDataLen )
		{
			iDataLen = sprintf_s (
				mcFieldName,
				sizeof(mcFieldName)/sizeof(*mcFieldName),
				"%s",
				"Unknown Field" );
		}

		iDataLen = sprintf_s (
			mcOutputData,
			sizeof(mcOutputData)/sizeof(*mcOutputData),
			"%d\t%d\t%s\r\n",
			p_psoTemplate->m_mpsoField[uiI]->m_wFieldType,
			p_psoTemplate->m_mpsoField[uiI]->m_wFieldSize,
			mcFieldName );

		m_pcoFileWriter->WriteData(
			(BYTE*)mcOutputData,
			iDataLen);
	}

	m_pcoFileWriter->WriteData(
		(BYTE*)"\r\n",
		2);
}

void CNFParser::OutputData(
	BYTE *p_pmbBuf,
	SNFv9Template *p_psoTemplate,
	SNFv9Header *p_psoHeader)
{
	BYTE mbValue[256];
	char mcValue[256];
	int iDataLen;
	std::map<DWORD,DWORD>::iterator iterOPT;

	for (UINT uiI = 0; uiI < p_psoTemplate->wFieldCount; ++uiI) 
	{
		if (m_bUseOPT) {
			iterOPT = m_mapOPT.find (p_psoTemplate->m_mpsoField[uiI]->m_wFieldType);
			if (iterOPT == m_mapOPT.end()) {
				p_pmbBuf += p_psoTemplate->m_mpsoField[uiI]->m_wFieldSize;
				continue;
			}
		}
		ZeroMemory (
			mbValue,
			sizeof(mbValue) );
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
			iDataLen = sprintf_s (
				mcValue,
				sizeof(mcValue)/sizeof(*mcValue),
				"%u.%u.%u.%u",
				((*((DWORD*)(mbValue))) & 0xFF000000) >> 24,
				((*((DWORD*)(mbValue))) & 0x00FF0000) >> 16,
				((*((DWORD*)(mbValue))) & 0x0000FF00) >> 8,
				((*((DWORD*)(mbValue))) & 0x000000FF) );
			break;
		case IDS_FIRST_SWITCHED:
		case IDS_LAST_SWITCHED:
			{
				DWORD dwUnixSec;
				int iTimeDelta;
				int iMilliSec;
				char mcUnixTime[32];

				// вычисляем на сколько время формирования пакета NetFlow
				// больше времени прохождения потока
				iTimeDelta = *((DWORD*)(mbValue)) - p_psoHeader->dwSysUpTime;

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

				iDataLen = sprintf_s (
					mcValue,
					"%s,%03d",
					mcUnixTime,
					iMilliSec );
			}
			break;
		default:
			if (IDS_OUT_BYTES == p_psoTemplate->m_mpsoField[uiI]->m_wFieldType
				|| IDS_IN_BYTES == p_psoTemplate->m_mpsoField[uiI]->m_wFieldType) {
					m_pcoStatKeeper->CountOctets (*((DWORD*)(mbValue)));
			}
			DWORD dwValue = *((DWORD*)(mbValue));
			switch (p_psoTemplate->m_mpsoField[uiI]->m_wFieldSize) {
			case 1: dwValue = 0x000000FF & dwValue; break;
			case 2: dwValue = 0x0000FFFF & dwValue; break;
			}
			iDataLen = sprintf_s(
				mcValue,
				sizeof(mcValue)/sizeof(*mcValue),
				"%u",
				dwValue);
		}

		if (m_bUseOPT) {
			strcpy_s (m_msoOPT[iterOPT->second].m_mcValue, sizeof(m_msoOPT[iterOPT->second].m_mcValue), mcValue);
			m_msoOPT[iterOPT->second].m_iDataSize = iDataLen;
		}
		else {
			if (! m_bDontOutputData) {
				m_pcoFileWriter->WriteData(
					(BYTE*)mcValue,
					iDataLen);

				if (uiI + 1 < p_psoTemplate->wFieldCount) {
					m_pcoFileWriter->WriteData(
						(BYTE*)"\t",
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
					(BYTE*)"\t",
					1);
			}
			m_pcoFileWriter->WriteData(
				(BYTE*)m_msoOPT[iInd].m_mcValue,
				m_msoOPT[iInd].m_iDataSize);
			m_msoOPT[iInd].m_mcValue[0] = '\0';
			m_msoOPT[iInd].m_iDataSize = 0;
		}
	}

	if (! m_bDontOutputData) {
		m_pcoFileWriter->WriteData(
			(BYTE*)"\r\n",
			2);
	}
}
