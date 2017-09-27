#pragma once

#pragma pack(push, 1)
    struct SNFv9FlowSet {
        uint16_t m_wFlowSetID;
        uint16_t m_wLength;
    };
    struct SNFv9Field {
        uint16_t m_wFieldType;
        uint16_t m_wFieldSize;
        uint32_t m_dwOffset;
    };
    struct SNFv9Template {
        uint16_t wTemplateID;
        uint16_t wFieldCount;
        uint16_t wDataSize;
        uint8_t *m_pmbMasterCopy;
        size_t m_stMasterCopySize;
        SNFv9Field **m_mpsoField;
    };
#pragma pack(pop)
