#pragma once
#include "common.h"
#include "nfpacket.h"
#include "v9packet.h"
#include "IpFixPacket.h"
#include "v9struct.h"
#include "FileReader.h"
#include "Filter.h"
#include "FileWriter.h"
#include "StatKeeper.h"

//class CFileWriter;
//class CFileReader;
//class CFilter;
//class CStatKeeper;
//class NFPacket;
//class V9Packet;
//class IpFixPacket;

#define	OUTPUT_NFPCKTHEADER	1
#define	OUTPUT_NFTEMPLATE		2
#define	OUTPUT_USEOPT				4
#define	OUTPUT_CNTPCKTS			8
#define	OUTPUT_DOD					16


/*	Шаблон вывода результатов
 */
struct SOutputTemplate {
	char m_mcFieldName[32];
	char m_mcValue[256];
	int m_iDataSize;
};



class CNFParser
{
public:
    CNFParser (bool p_bCountPackets = false);
    bool Init(
		CFileWriter *p_pcoFileWriter,
		CFileReader *p_pcoFileReader,
		CFilter *p_pcoFilter,
		CStatKeeper *p_pcoStatKeeper,
        uint32_t p_dwFlags);
    bool ReadNFPacket();

private:
    void OutputTemplate(
        uint32_t p_dwSrcId,
        SNFv9Template *p_psoTemplate);
    void OutputData(uint8_t *p_pmbBuf,
        SNFv9Template *p_psoTemplate,
        V9Packet *p_psoHeader);
private:
	CFileWriter *m_pcoFileWriter;
	CFileReader *m_pcoFileReader;
	CFilter *m_pcoFilter;
	CStatKeeper *m_pcoStatKeeper;
    std::map<uint32_t,uint32_t> m_mapOPT;
    std::map<uint64_t,SNFv9Template*> m_mapTemplates;
	SOutputTemplate m_msoOPT[7];
    bool m_bOutputHeader;
    bool m_bOutputTemplate;
    bool m_bUseOPT;
    bool m_bCountPackets;
    bool m_bDontOutputData;

    friend class V9Packet;
};




