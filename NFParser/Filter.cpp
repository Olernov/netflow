#include "NFParser.h"
#include "Filter.h"

BOOL CFilter::SetParameter(
	DWORD p_dwParamId,
	void *p_pvParamVal,
	DWORD p_dwValSize)
{
	void *pvValue = NULL;
	DWORD dwValSize = 0;

	if (! GetParam(
		p_dwParamId,
		&pvValue,
		&dwValSize)) {
			return FALSE;
	}

	if (pvValue
		&& dwValSize) {
			ZeroMemory(
				pvValue,
				dwValSize);
			dwValSize = dwValSize < p_dwValSize ?
				dwValSize
				: p_dwValSize;
			memcpy(
				pvValue,
				p_pvParamVal,
				dwValSize);
	}
	else {
		return FALSE;
	}

	return TRUE;
}


BOOL CFilter::RowFilter(
	SNFv9Header *p_psoHeader,
	SNFv9Template *p_psoTemplate,
	BYTE *p_pmbBuf)
{
	DWORD dwValue;
	WORD wValue;
	int iDelta;
	DWORD dwSysUpTime;
	DWORD dwFlowTime;
	DWORD dwUnixTime;

	for (DWORD dwI = 0; dwI < p_psoTemplate->wFieldCount; ++dwI) {

		dwValue = 0;
		memcpy(
			&dwValue,
			&(p_pmbBuf[p_psoTemplate->m_mpsoField[dwI]->m_dwOffset]),
			sizeof(dwValue) < p_psoTemplate->m_mpsoField[dwI]->m_wFieldSize ?
				sizeof(dwValue)
				: p_psoTemplate->m_mpsoField[dwI]->m_wFieldSize);
		switch (p_psoTemplate->m_mpsoField[dwI]->m_wFieldType) {
			case IDS_IPV4_SRC_ADDR:
				if (-1 != m_dwSrcIp) {
					dwValue = ntohl (dwValue);
					if ((dwValue & m_dwSrcMask) != (m_dwSrcIp & m_dwSrcMask)
						|| dwValue < m_dwSrcIp) {
							return FALSE;
					}
				}
				break;
			case IDS_IPV4_DST_ADDR:
				if (-1 != m_dwDstIp) {
					dwValue = ntohl (dwValue);
					if ((dwValue & m_dwDstMask) != (m_dwDstIp & m_dwDstMask)
						|| dwValue < m_dwDstIp) {
							return FALSE;
					}
				}
				break;
			case IDS_FIRST_SWITCHED:
				if (-1 != m_dwStartTime) {
					dwFlowTime = ntohl (dwValue);
					dwSysUpTime = p_psoHeader->dwSysUpTime;
					iDelta = (int)(dwFlowTime - dwSysUpTime)/1000;
					dwUnixTime = p_psoHeader->dwUnixSeconds;
					if (m_dwStartTime > dwUnixTime + iDelta) {
						return FALSE;
					}
				}
				break;
			case IDS_LAST_SWITCHED:
				if (-1 != m_dwStopTime) {
					dwFlowTime = ntohl (dwValue);
					dwSysUpTime = p_psoHeader->dwSysUpTime;
					iDelta = (int)(dwFlowTime - dwSysUpTime)/1000;
					dwUnixTime = p_psoHeader->dwUnixSeconds;
					if (m_dwStopTime < dwUnixTime + iDelta) {
						return FALSE;
					}
				}
				break;
			case IDS_L4_SRC_PORT:
				if ((WORD)-1 != m_wSrcPort) {
					wValue = (WORD)dwValue;
					wValue = ntohs (wValue);
					if (wValue != m_wSrcPort) {
						return FALSE;
					}
				}
				break;
			case IDS_L4_DST_PORT:
				if ((WORD)-1 != m_wDstPort) {
					wValue = (WORD)dwValue;
					wValue = ntohs (wValue);
					if (wValue != m_wDstPort) {
						return FALSE;
					}
				}
				break;
			default:
				break;
		}
	}

	return TRUE;
}


BOOL CFilter::ParamFilter(
	DWORD p_dwParamId,
	void *p_pvParamVal,
	DWORD p_dwValSize)
{
	void *pvParam = NULL;
	DWORD dwValSize;

	if (! GetParam(
		p_dwParamId,
		&pvParam,
		&dwValSize)) {
			return TRUE;
	}

	if (pvParam
		&& dwValSize) {
			dwValSize = dwValSize < p_dwValSize ?
				dwValSize
				: p_dwValSize;
			if (0 == memcmp(
				pvParam,
				p_pvParamVal,
				dwValSize)) {
					return TRUE;
			}
	}

	return FALSE;
}


BOOL CFilter::FileFilter (const char *p_pcszFileName)
{
	int iFnRes;
	DWORD dwRouterIp;
	ULONGLONG ullFileTime;
	DWORD dwFileTime;

	iFnRes = sscanf_s(
		p_pcszFileName,
		"%x_%I64u",
		&dwRouterIp,
		&ullFileTime);
	if (2 != iFnRes) {
		return FALSE;
	}
	if ((ULONGLONG)20110400000000 <= ullFileTime) {
		tm soTm;
		// выдел€ем секунды
		soTm.tm_sec = ullFileTime%100;
		ullFileTime /= 100;
		// выдел€ем минуты
		soTm.tm_min = ullFileTime%100;
		ullFileTime /= 100;
		// выдел€ем часы
		soTm.tm_hour = ullFileTime%100;
		ullFileTime /= 100;
		// выдел€ем день мес€ца
		soTm.tm_mday = ullFileTime%100;
		ullFileTime /= 100;
		// выдел€ем мес€ц
		soTm.tm_mon = ullFileTime%100;
		--soTm.tm_mon;
		ullFileTime /= 100;
		// должен был остатьс€ только год
		soTm.tm_year = (int)ullFileTime;
		soTm.tm_year -= 1900;
		dwFileTime = (DWORD) mktime (&soTm);
	}
	else {
		dwFileTime = (DWORD)ullFileTime;
	}
	if (m_dwStartTime != -1
		&& m_dwStartTime > dwFileTime + 360) {
		return FALSE;
	}
	if (m_dwStopTime != -1
		&& m_dwStopTime < dwFileTime - 720) {
		return FALSE;
	}

	return TRUE;
}


CFilter::CFilter(void)
{
	m_dwSrcIp = -1;
	m_dwSrcMask = -1;
	m_dwDstIp = -1;
	m_dwDstMask = -1;
	m_dwStartTime = -1;
	m_dwStopTime = -1;
	m_wSrcPort = -1;
	m_wDstPort = -1;
}


CFilter::~CFilter(void)
{
}


BOOL CFilter::GetParam(
	DWORD p_dwParamId,
	void **p_pvParamVal,
	DWORD *p_pdwValSize)
{
	switch (p_dwParamId) {
	case IDS_FIRST_SWITCHED:
		*p_pvParamVal = &m_dwStartTime;
		*p_pdwValSize = sizeof(m_dwStartTime);
		break;
	case IDS_LAST_SWITCHED:
		*p_pvParamVal = &m_dwStopTime;
		*p_pdwValSize = sizeof(m_dwStopTime);
		break;
	case IDS_IPV4_SRC_ADDR:
		*p_pvParamVal = &m_dwSrcIp;
		*p_pdwValSize = sizeof(m_dwSrcIp);
		break;
	case IDS_SRC_MASK:
		*p_pvParamVal = &m_dwSrcMask;
		*p_pdwValSize = sizeof(m_dwSrcMask);
		break;
	case IDS_IPV4_DST_ADDR:
		*p_pvParamVal = &m_dwDstIp;
		*p_pdwValSize = sizeof(m_dwDstIp);
		break;
	case IDS_DST_MASK:
		*p_pvParamVal = &m_dwDstMask;
		*p_pdwValSize = sizeof(m_dwDstMask);
		break;
	case IDS_L4_SRC_PORT:
		*p_pvParamVal = &m_wSrcPort;
		*p_pdwValSize = sizeof(m_wSrcPort);
		break;
	case IDS_L4_DST_PORT:
		*p_pvParamVal = &m_wDstPort;
		*p_pdwValSize = sizeof(m_wDstPort);
		break;
	default:
		return FALSE;
	}

	return TRUE;
}
