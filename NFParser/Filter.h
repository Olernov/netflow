#pragma once

struct SNFv9Header;
struct SNFv9Template;

class CFilter
{
public:
	BOOL SetParameter(
		DWORD p_dwParamId,
		void *p_pvParamVal,
		DWORD p_dwValSize);
	BOOL RowFilter(
		SNFv9Header *p_psoHeader,
		SNFv9Template *p_psoTemplate,
		BYTE *p_pmbBuf);
	BOOL ParamFilter(
		DWORD p_dwParamId,
		void *p_pvParamVal,
		DWORD p_dwValSize);
	BOOL FileFilter (const char *p_pcszFileName);
public:
	CFilter(void);
	~CFilter(void);
private:
	BOOL GetParam(
		DWORD p_dwParamId,
		void **p_pvParamVal,
		DWORD *p_pdwValSize);
private:
	DWORD m_dwSrcIp;
	DWORD m_dwSrcMask;
	DWORD m_dwDstIp;
	DWORD m_dwDstMask;
	DWORD m_dwStartTime;
	DWORD m_dwStopTime;
	WORD m_wSrcPort;
	WORD m_wDstPort;
};
