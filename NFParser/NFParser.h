#pragma once
#include "common.h"

class CFileWriter;
class CFileReader;
class CFilter;
class CStatKeeper;

#define	OUTPUT_NFPCKTHEADER	1
#define	OUTPUT_NFTEMPLATE		2
#define	OUTPUT_USEOPT				4
#define	OUTPUT_CNTPCKTS			8
#define	OUTPUT_DOD					16

#pragma pack(push, 1)
	/* заголовок пакета NetFlow v9
	 */
	struct SNFv9Header {
        uint16_t wVersion;
        uint16_t wCount;
        uint32_t dwSysUpTime;
        uint32_t dwUnixSeconds;
        uint32_t dwSeqNumber;
        uint32_t dwSrcId;
	};
	/* заголовок записи NetFlow v9
	 */
	struct SNFv9FlowSet {
        uint16_t m_wFlowSetID;
        uint16_t m_wLength;
	};
	/* заголовок поля NetFlow v9
	 */
	struct SNFv9Field {
        uint16_t m_wFieldType;
        uint16_t m_wFieldSize;
        uint32_t m_dwOffset;
	};
	/* заголовок шаблона NetFlow v9
	 */
	struct SNFv9Template {
        uint16_t wTemplateID;
        uint16_t wFieldCount;
        uint16_t wDataSize;
        uint8_t *m_pmbMasterCopy;
		size_t m_stMasterCopySize;
		SNFv9Field **m_mpsoField;
	};
#pragma pack(pop)

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
    bool Init(
		CFileWriter *p_pcoFileWriter,
		CFileReader *p_pcoFileReader,
		CFilter *p_pcoFilter,
		CStatKeeper *p_pcoStatKeeper,
        uint32_t p_dwFlags);
    bool ReadNFPacket();
public:
    CNFParser (bool p_bCountPackets = false);
	~CNFParser(void);
private:
    uint32_t ParseNFHeader(
        uint8_t *p_pmbBuf,
		int p_iPackLen,
		SNFv9Header *p_psoNFv9Hdr);
	// функция возвращает количество обработанных записей
    uint32_t ParseFlowSet (SNFv9Header *p_psoHeader);
	int ParseTemplateFlowSet(
		SNFv9Header *p_psoHeader,
        uint8_t *p_pmbBuf,
		size_t p_stDataSize);
	void ParseDataFlowSet(
		SNFv9Header *p_psoHeader,
		SNFv9Template *p_psoTemplate,
        uint8_t *p_pmbBuf,
        uint32_t p_dwRecordCount);
	void UnixTimeToStr(
        uint32_t p_dwUnixTime,
		char *m_pmcOutputStr,
		size_t p_stMaxChars);
	void CopyBlock(
        uint8_t *p_pmbDst,
		size_t p_stDstSize,
        uint8_t *p_pmbSrc,
        size_t p_stuint8_tsToCopy);
	void OutputHeader (SNFv9Header *p_psoHeader);
	void OutputTemplate(
        uint32_t p_dwSrcId,
		SNFv9Template *p_psoTemplate);
	void OutputData(
        uint8_t *p_pmbBuf,
		SNFv9Template *p_psoTemplate,
		SNFv9Header *p_psoHeader);
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
};
