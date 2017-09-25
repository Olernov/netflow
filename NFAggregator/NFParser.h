#pragma once
#include "Common.h"
#include "DataRecord.h"
#include "Aggregator.h"

class CFileReader;

#define	OUTPUT_NFPCKTHEADER	1
#define	OUTPUT_NFTEMPLATE		2
#define	OUTPUT_USEOPT				4
#define	OUTPUT_CNTPCKTS			8
#define	OUTPUT_DOD					16

#define IDS_IN_BYTES                    1
#define IDS_IN_PKTS                     2
#define IDS_FLOWS                       3
#define IDS_PROTOCOL                    4
#define IDS_SRC_TOS                     5
#define IDS_TCP_FLAGS                   6
#define IDS_L4_SRC_PORT                 7
#define IDS_IPV4_SRC_ADDR               8
#define IDS_SRC_MASK                    9
#define IDS_INPUT_SNMP                  10
#define IDS_L4_DST_PORT                 11
#define IDS_IPV4_DST_ADDR               12
#define IDS_DST_MASK                    13
#define IDS_OUTPUT_SNMP                 14
#define IDS_IPV4_NEXT_HOP               15
#define IDS_SRC_AS                      16
#define IDS_DST_AS                      17
#define IDS_BGP_IPV4_NEXT_HOP           18
#define IDS_MUL_DST_PKTS                19
#define IDS_MUL_DST_BYTES               20
#define IDS_LAST_SWITCHED               21
#define IDS_FIRST_SWITCHED              22
#define IDS_OUT_BYTES                   23
#define IDS_OUT_PACKETS                 24
#define IDS_MIN_PKT_LNGTH               25
#define IDS_MAX_PKT_LNGTH               26
#define IDS_IPV6_SRC_ADDR               27
#define IDS_IPV6_DST_ADDR               28
#define IDS_IPV6_SRC_MASK               29
#define IDS_IPV6_DST_MASK               30
#define IDS_IPV6_FLOW_LABEL             31
#define IDS_ICMP_TYPE                   32
#define IDS_MUL_IGMP_TYPE               33
#define IDS_SAMPLING_INTERVAL           34
#define IDS_SAMPLING_ALGORITHM          35
#define IDS_FLOW_ACTIVE_TIMEOUT         36
#define IDS_FLOW_INACTIVE_TIMEOUT       37
#define IDS_ENGINE_TYPE                 38
#define IDS_ENGINE_ID                   39
#define IDS_TOTAL_BYTES_EXP             40
#define IDS_TOTAL_PKTS_EXP              41
#define IDS_TOTAL_FLOWS_EXP             42
#define IDS_IPV4_SRC_PREFIX             44
#define IDS_IPV4_DST_PREFIX             45
#define IDS_MPLS_TOP_LABEL_TYPE         46
#define IDS_MPLS_TOP_LABEL_IP_ADDR      47
#define IDS_FLOW_SAMPLER_ID             48
#define IDS_FLOW_SAMPLER_MODE           49
#define IDS_FLOW_SAMPLER_RANDOM_INTERVAL 50
#define IDS_MIN_TTL                     52
#define IDS_MAX_TTL                     53
#define IDS_IPV4_IDENT                  54
#define IDS_DST_TOS                     55
#define IDS_IN_SRC_MAC                  56
#define IDS_OUT_DST_MAC                 57
#define IDS_SRC_VLAN                    58
#define IDS_DST_VLAN                    59
#define IDS_IP_PROTOCOL_VERSION         60
#define IDS_DIRECTION                   61
#define IDS_IPV6_NEXT_HOP               62
#define IDS_BPG_IPV6_NEXT_HOP           63
#define IDS_IPV6_OPTION_HEADERS         64
#define IDS_MPLS_LABEL_1                70
#define IDS_MPLS_LABEL_2                71
#define IDS_MPLS_LABEL_3                72
#define IDS_MPLS_LABEL_4                73
#define IDS_MPLS_LABEL_5                74
#define IDS_MPLS_LABEL_6                75
#define IDS_MPLS_LABEL_7                76
#define IDS_MPLS_LABEL_8                77
#define IDS_MPLS_LABEL_9                78
#define IDS_MPLS_LABEL_10               79
#define IDS_IN_DST_MAC                  80
#define IDS_OUT_SRC_MAC                 81
#define IDS_IF_NAME                     82
#define IDS_IF_DESC                     83
#define IDS_SAMPLER_NAME                84
#define IDS_IN_PERMANENT_BYTES          85
#define IDS_IN_PERMANENT_PKTS           86
#define IDS_FRAGMENT_OFFSET             88


#pragma pack(push, 1)

	struct SNFv9Header {
        uint16_t wVersion;
        uint16_t wCount;
        uint32_t dwSysUpTime;
        uint32_t dwUnixSeconds;
        uint32_t dwSeqNumber;
        uint32_t dwSrcId;
	};

    struct SNFv9FlowSet {
        uint16_t m_wFlowSetID;
        uint16_t m_wLength;
	};

    struct SNFv9Field {
        uint16_t fieldType;
        uint16_t fieldSize;
        uint32_t offset;
	};

    struct SNFv9Template {
        uint16_t templateID;
        uint16_t fieldCount;
        uint16_t dataSize;
        uint8_t *masterCopy;
        size_t masterCopySize;
        SNFv9Field **field;
	};
#pragma pack(pop)


class CNFParser
{
public:
    void Initialize(Aggregator* aggr);
    bool ProcessNextExportPacket(CFileReader& fileReader);

private:
    uint32_t ParseNFHeader(uint8_t *buffer,
        int packetLen,
        SNFv9Header *nfHeader);
    // function returns count of processed records
    uint32_t ParseFlowSet (CFileReader& fileReader, SNFv9Header *p_psoHeader);
    int ParseTemplateFlowSet(SNFv9Header *nfHeader,
        uint8_t *buffer,
        size_t dataSize);
    void ParseDataFlowSet(SNFv9Header *p_psoHeader,
        SNFv9Template *p_psoTemplate,
        uint8_t *p_pmbBuf,
        uint32_t recordCount);
    void CopyBlock(uint8_t *dest,
        size_t destSize,
        uint8_t *src,
        size_t bytesToCopy);
    bool ParseDataRecord(uint8_t *p_pmbBuf,
        SNFv9Template *nfTemplate,
        SNFv9Header *nfHeader, DataRecord *dataRecord);
private:
    Aggregator* aggregator;
    std::map<uint64_t,SNFv9Template*> m_mapTemplates;

    template<typename T>
    bool ReadInteger(uint8_t* rawData, int fieldSize, T& value) {
        if (fieldSize > sizeof(value)) {
            return false;
        }
        value = 0;
        for (int i = 0; i < fieldSize; ++i) {
            value <<= 8;
            value |= *rawData;
            ++rawData;
        }
        return true;
    }

    bool ParseSwitchedTime(uint8_t* rawData, int fieldSize, SNFv9Header* nfHeader, time_t& switchedTime);
};
