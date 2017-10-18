#pragma once
#include "nfpacket.h"
#include "NFStruct.h"
#include "NFParser.h"


class V9Packet : public NFPacket {
public:
    V9Packet(CNFParser* nfParser);
    virtual bool ParseHeader();
    virtual bool ParseBody();

private:
    struct {
        uint16_t count;
        uint32_t sysUpTime;
        uint32_t unixSeconds;
        uint32_t seqNumber;
        uint32_t sourceId;
    } headerInfo;

    virtual uint32_t GetDomainID() const {
        return headerInfo.sourceId;
    }

    virtual void OutputHeader();
    virtual void CountStats();
//    uint32_t ParseFlowSet();
//    int ParseTemplateFlowSet(uint8_t *buffer, size_t dataSize);
//    void ParseDataFlowSet(
//        FlowTemplate *nfTemplate,
//        uint8_t *buffer,
//        uint32_t recordCount);
};
