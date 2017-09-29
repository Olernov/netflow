#include <memory.h>
#include "NFParser.h"



void UnixTimeToStr(
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



void CopyBlock(
    uint8_t *p_pmbDst,
    size_t p_stDstSize,
    uint8_t *p_pmbSrc,
    size_t p_stBytesToCopy)
{
    size_t stuint8_tsToCopy;
    size_t stWriteInd = 0;

    stuint8_tsToCopy = p_stBytesToCopy > p_stDstSize ?
        p_stDstSize :
        p_stBytesToCopy;

    while ( stuint8_tsToCopy )
    {
        -- stuint8_tsToCopy;
        p_pmbDst[stWriteInd] = p_pmbSrc[stuint8_tsToCopy];
        ++ stWriteInd;
    }
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
    uint8_t *buffer;
    if (m_pcoFileReader == nullptr) {
        return false;
    }
    size_t stBytesRead = m_pcoFileReader->ReadData(&buffer, NFPacket::VERSION_FIELD_SIZE);
    if (stBytesRead != NFPacket::VERSION_FIELD_SIZE) {
        return false;
    }
    uint16_t version = ntohs (*((u_short*)buffer));
    if (version != 9 && version != 10) {
        char mcMsg[256];
        size_t stMsgLen;

        stMsgLen = snprintf(
            mcMsg,
            sizeof(mcMsg),
            "Error: invalid version number: %u\r\n",
            version);
        m_pcoFileWriter->WriteData(
            (uint8_t*)mcMsg,
            stMsgLen);
        m_pcoFileWriter->Finalise();
        return false;
    }

    NFPacket* nfPacket = nullptr;
    if (version == NETFLOW_V9) {
        nfPacket = new V9Packet(this);
    }
    else if (version == IPFIX) {
        nfPacket = new IpFixPacket(this);
    }
    if (!nfPacket->ParseHeader()) {
        return false;
    }
    if (m_bCountPackets) {
        nfPacket->CountStats();
    }

    if (m_bOutputHeader) {
        nfPacket->OutputHeader();
    }
    bool parseRes = nfPacket->ParseBody();

    delete nfPacket;
    return parseRes;
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
    V9Packet *p_psoHeader)
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
                iTimeDelta = *((uint32_t*)(mbValue)) - p_psoHeader->sysUpTime;

                // определяем кличество тысячных долей секунды
                iMilliSec = iTimeDelta % 1000;

                // определяем время прохождения потока
                dwUnixSec = p_psoHeader->unixSeconds + iTimeDelta/1000;

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
