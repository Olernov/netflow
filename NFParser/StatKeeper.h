#pragma once

class CFileWriter;

struct SPackSeq {
	int m_iDelta;
	DWORD m_dwLastSeqNum;
	unsigned __int64 m_ui64PackCount;
};

struct SSourceInfo {
	char m_mcDir[MAX_PATH];
	DWORD m_dwSourceId;
};

class CStatKeeper
{
public:
	void CountFile(
		const char *p_pcszFileName,
		BOOL p_bSkipped);
	void CountOctets (ULONGLONG p_ullOctets);
	void CountPacket (const char *p_pcszDir, DWORD p_dwSrcId, DWORD p_dwSeqNum);
	void OutputStat (CFileWriter *p_pcoFileWriter);
public:
	CStatKeeper(void);
	~CStatKeeper(void);
private:
	std::map<DWORD,DWORD> m_mapStat;
	DWORD m_dwSkipped;
	DWORD m_dwOperated;
	ULONGLONG m_ullOctets;
	ULONGLONG m_ullRecordNum;
	std::map<SSourceInfo,SPackSeq> m_mapPackSeq;
};
