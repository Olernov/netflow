#pragma once

struct DataRecord
{
    DataRecord() :
        firstSwitched(0),
        lastSwitched(0),
        inBytes(0),
        outBytes(0),
        srcPort(0),
        srcIpAddr(0),
        dstPort(0),
        dstIpAddr(0)
    {}

    time_t firstSwitched;
    time_t lastSwitched;
    uint64_t inBytes;
    uint64_t outBytes;
    uint16_t srcPort;
    uint32_t srcIpAddr;
    uint16_t dstPort;
    uint32_t dstIpAddr;
};
