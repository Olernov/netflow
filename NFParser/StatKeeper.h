#pragma once
#include "common.h"
#include <map>

class CFileWriter;

struct SPackSeq {
	int m_iDelta;
    unsigned long m_dwLastSeqNum;
    uint64_t m_ui64PackCount;
};

struct SSourceInfo {
	char m_mcDir[MAX_PATH];
    unsigned long m_dwSourceId;
};

class CStatKeeper
{
public:
	void CountFile(
		const char *p_pcszFileName,
        bool p_bSkipped);
    void CountOctets (uint64_t p_ullOctets);
    void CountPacket (const char *p_pcszDir, uint32_t p_dwSrcId, uint32_t p_dwSeqNum);
	void OutputStat (CFileWriter *p_pcoFileWriter);
public:
	CStatKeeper(void);
	~CStatKeeper(void);
private:
    std::map<uint32_t, uint32_t> m_mapStat;
    uint32_t m_dwSkipped;
    uint32_t m_dwOperated;
    uint64_t m_ullOctets;
    uint64_t m_ullRecordNum;
	std::map<SSourceInfo,SPackSeq> m_mapPackSeq;
};
