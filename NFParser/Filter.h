#pragma once
#include "common.h"

struct NFPacket;
struct V9Packet;
struct FlowTemplate;

class CFilter
{
public:
    bool SetParameter(
        uint32_t p_dwParamId,
		void *p_pvParamVal,
        uint32_t p_dwValSize);
    bool RowFilter(V9Packet *p_psoHeader,
        FlowTemplate *p_psoTemplate,
        uint8_t *p_pmbBuf);
    bool ParamFilter(
        uint32_t p_dwParamId,
		void *p_pvParamVal,
        uint32_t p_dwValSize);
    bool FileFilter (const char *p_pcszFileName);
public:
	CFilter(void);
	~CFilter(void);
private:
    bool GetParam(
        uint32_t p_dwParamId,
		void **p_pvParamVal,
        uint32_t *p_pdwValSize);
private:
    uint32_t m_dwSrcIp;
    uint32_t m_dwSrcMask;
    uint32_t m_dwDstIp;
    uint32_t m_dwDstMask;
    uint32_t m_dwStartTime;
    uint32_t m_dwStopTime;
    uint16_t m_wSrcPort;
    uint16_t m_wDstPort;
};
