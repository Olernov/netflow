#pragma once

struct DataRecord
{
    time_t firstSwitched;
    time_t lastSwitched;
    uint64_t inBytes;
    uint64_t outBytes;
    uint16_t srcPort;
    uint32_t srcIpAddr;
    uint16_t dstPort;
    uint32_t dstIpAddr;
};
