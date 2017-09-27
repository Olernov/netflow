#pragma once
#include "nfpacket.h"
#include "v9struct.h"
#include "NFParser.h"


struct V9Packet : public NFPacket {
    V9Packet(CNFParser* nfParser);
    uint16_t count;
    uint32_t sysUpTime;
    uint32_t unixSeconds;
    uint32_t seqNumber;
    uint32_t srcId;

    virtual bool ParseHeader();
    virtual bool ParseBody();
    virtual void OutputHeader();
    virtual void CountStats();
    uint32_t ParseFlowSet();
    int ParseTemplateFlowSet(uint8_t *buffer, size_t dataSize);
    void ParseDataFlowSet(
        SNFv9Template *nfTemplate,
        uint8_t *buffer,
        uint32_t recordCount);
};
