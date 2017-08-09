#include <string.h>
#include <time.h>
#include "StatKeeper.h"
#include "FileWriter.h"


bool operator < (
	const SSourceInfo &p_soLeft,
	const SSourceInfo &p_soRight)
{
	int iCmpRes;

	iCmpRes = strcmp (p_soLeft.m_mcDir, p_soRight.m_mcDir);
	if (0 == iCmpRes) {
		return p_soLeft.m_dwSourceId < p_soRight.m_dwSourceId;
	}
	if (0 > iCmpRes) {
        return true;
	}
	else {
        return false;
	}
}

void CStatKeeper::CountFile(
	const char *p_pcszFileName,
    bool p_bSkipped)
{
    if (p_pcszFileName == nullptr) {
		return;
	}

	if (p_bSkipped) {
		++ m_dwSkipped;
	}
	else {
        ++m_dwOperated;
	}

    uint32_t dwCap;
    uint32_t dwTimeStamp;
    uint64_t ullTimeStamp;

    sscanf(
		p_pcszFileName,
		"%x_%I64u",
		&dwCap,
		&ullTimeStamp);

    if ((uint64_t)20110400000000 <= ullTimeStamp) {
		tm soTm;
        soTm.tm_sec = ullTimeStamp%100;
		ullTimeStamp /= 100;
        soTm.tm_min = ullTimeStamp%100;
		ullTimeStamp /= 100;
        soTm.tm_hour = ullTimeStamp%100;
		ullTimeStamp /= 100;
        soTm.tm_mday = ullTimeStamp%100;
		ullTimeStamp /= 100;
        soTm.tm_mon = ullTimeStamp%100;
		--soTm.tm_mon;
		ullTimeStamp /= 100;
        soTm.tm_year = (int)ullTimeStamp;
		soTm.tm_year -= 1900;
        dwTimeStamp = (uint32_t) mktime (&soTm);
	}
	else {
        dwTimeStamp = (uint32_t)ullTimeStamp;
	}

    // Truncate hours, minutes and seconds
	dwTimeStamp /= 86400;
	dwTimeStamp *= 86400;

    std::map<uint32_t, uint32_t>::iterator iterStat;

	iterStat = m_mapStat.find (dwTimeStamp);

	if (iterStat != m_mapStat.end()) {
		++(iterStat->second);
	}
	else {
		m_mapStat.insert(
			std::make_pair(
				dwTimeStamp,
				1));
	}
}

void CStatKeeper::CountOctets (uint64_t p_ullOctets)
{
	m_ullOctets += p_ullOctets;
	++m_ullRecordNum;
}

void CStatKeeper::CountPacket (const char *p_pcszDir, uint32_t p_dwSrcId, uint32_t p_dwSeqNum)
{
	std::map<SSourceInfo,SPackSeq>::iterator iterSeq;
	SSourceInfo soSrcInfo;

    strncpy(soSrcInfo.m_mcDir, p_pcszDir, sizeof(soSrcInfo.m_mcDir));
	soSrcInfo.m_dwSourceId = p_dwSrcId;

	iterSeq = m_mapPackSeq.find (soSrcInfo);

	if (iterSeq != m_mapPackSeq.end()) {
		iterSeq->second.m_iDelta += 1 + iterSeq->second.m_dwLastSeqNum - p_dwSeqNum;
		iterSeq->second.m_dwLastSeqNum = p_dwSeqNum;
		++(iterSeq->second.m_ui64PackCount);
	}
	else {
		SPackSeq soPackSeq = {0, p_dwSeqNum, 1};
		m_mapPackSeq.insert(
			std::make_pair(
				soSrcInfo,
				soPackSeq));
	}
}

void CStatKeeper::OutputStat (CFileWriter *p_pcoFileWriter)
{
	char mcMsg[0x2000];
	size_t stMsgLen;

    stMsgLen = snprintf(
		mcMsg,
        sizeof(mcMsg),
		"\r\nTotal octets: %lld\r\nTotal records: %lld\r\n",
		m_ullOctets,
		m_ullRecordNum);
	p_pcoFileWriter->WriteData(
        (uint8_t*)mcMsg,
		stMsgLen);

    stMsgLen = snprintf(
		mcMsg,
        sizeof(mcMsg),
		"\r\nFiles skipped: %u\r\nFiles operated: %u\r\n",
		m_dwSkipped,
		m_dwOperated);
	p_pcoFileWriter->WriteData(
        (uint8_t*)mcMsg,
		stMsgLen);

	std::map<SSourceInfo,SPackSeq>::iterator iterPackSeq;

	iterPackSeq = m_mapPackSeq.begin();
	while (iterPackSeq != m_mapPackSeq.end()) {
        stMsgLen = snprintf(
			mcMsg,
            sizeof(mcMsg),
			"Directory: %s; Source ID: 0x%08x; Number of missed packets: %d; Last sequence number: %u; Total packet number: %i64\r\n",
			iterPackSeq->first.m_mcDir,
			iterPackSeq->first.m_dwSourceId,
			iterPackSeq->second.m_iDelta,
			iterPackSeq->second.m_dwLastSeqNum,
			iterPackSeq->second.m_ui64PackCount);
		p_pcoFileWriter->WriteData(
            (uint8_t*)mcMsg,
			stMsgLen);
		++iterPackSeq;
	}

    std::map<uint32_t, uint32_t>::iterator iterStat;
	time_t ttTime;
	tm soTime;
	char mcTime[128];

	iterStat = m_mapStat.begin();
	while (iterStat != m_mapStat.end()) {
		ttTime = (time_t) iterStat->first;
        gmtime_r ( &ttTime, &soTime );
		strftime (
			mcTime,
			sizeof(mcTime),
			"%d.%m.%Y %H:%M:%S",
			&soTime );
		printf(
			"%s: %u\n",
			mcTime,
			iterStat->second);
		++iterStat;
	}
}

CStatKeeper::CStatKeeper(void)
{
	m_dwSkipped = 0;
	m_dwOperated = 0;
	m_ullOctets = 0;
	m_ullRecordNum = 0;
}

CStatKeeper::~CStatKeeper(void)
{
}
