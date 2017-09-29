#pragma once

#pragma pack(push, 1)
    struct FlowSetHeader {
        uint16_t m_wFlowSetID;
        uint16_t m_wLength;
    };
    struct FlowField {
        uint16_t m_wFieldType;
        uint16_t m_wFieldSize;
        uint32_t m_dwOffset;
    };
    struct FlowTemplate {
        uint16_t wTemplateID;
        uint16_t wFieldCount;
        uint16_t wDataSize;
        uint8_t *m_pmbMasterCopy;
        size_t m_stMasterCopySize;
        FlowField **m_mpsoField;
    };
#pragma pack(pop)
