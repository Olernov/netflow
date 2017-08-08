#pragma once

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
		WORD wVersion;
		WORD wCount;
		DWORD dwSysUpTime;
		DWORD dwUnixSeconds;
		DWORD dwSeqNumber;
		DWORD dwSrcId;
	};
	/* заголовок записи NetFlow v9
	 */
	struct SNFv9FlowSet {
		WORD m_wFlowSetID;
		WORD m_wLength;
	};
	/* заголовок поля NetFlow v9
	 */
	struct SNFv9Field {
		WORD m_wFieldType;
		WORD m_wFieldSize;
		DWORD m_dwOffset;
	};
	/* заголовок шаблона NetFlow v9
	 */
	struct SNFv9Template {
		WORD wTemplateID;
		WORD wFieldCount;
		WORD wDataSize;
		BYTE *m_pmbMasterCopy;
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
	BOOL Init(
		CFileWriter *p_pcoFileWriter,
		CFileReader *p_pcoFileReader,
		CFilter *p_pcoFilter,
		CStatKeeper *p_pcoStatKeeper,
		DWORD p_dwFlags);
	BOOL ReadNFPacket();
public:
	CNFParser (BOOL p_bCountPackets = FALSE);
	~CNFParser(void);
private:
	DWORD ParseNFHeader(
		BYTE *p_pmbBuf,
		int p_iPackLen,
		SNFv9Header *p_psoNFv9Hdr);
	// функция возвращает количество обработанных записей
	DWORD ParseFlowSet (SNFv9Header *p_psoHeader);
	int ParseTemplateFlowSet(
		SNFv9Header *p_psoHeader,
		BYTE *p_pmbBuf,
		size_t p_stDataSize);
	void ParseDataFlowSet(
		SNFv9Header *p_psoHeader,
		SNFv9Template *p_psoTemplate,
		BYTE *p_pmbBuf,
		DWORD p_dwRecordCount);
	void UnixTimeToStr(
		DWORD p_dwUnixTime,
		char *m_pmcOutputStr,
		size_t p_stMaxChars);
	void CopyBlock(
		BYTE *p_pmbDst,
		size_t p_stDstSize,
		BYTE *p_pmbSrc,
		size_t p_stBytesToCopy);
	void OutputHeader (SNFv9Header *p_psoHeader);
	void OutputTemplate(
		DWORD p_dwSrcId,
		SNFv9Template *p_psoTemplate);
	void OutputData(
		BYTE *p_pmbBuf,
		SNFv9Template *p_psoTemplate,
		SNFv9Header *p_psoHeader);
private:
	CFileWriter *m_pcoFileWriter;
	CFileReader *m_pcoFileReader;
	CFilter *m_pcoFilter;
	CStatKeeper *m_pcoStatKeeper;
	std::map<DWORD,DWORD> m_mapOPT;
	std::map<ULONGLONG,SNFv9Template*> m_mapTemplates;
	SOutputTemplate m_msoOPT[7];
	BOOL m_bOutputHeader;
	BOOL m_bOutputTemplate;
	BOOL m_bUseOPT;
	BOOL m_bCountPackets;
	BOOL m_bDontOutputData;
};
