#pragma once
#include "nfpacket.h"
#include "NFStruct.h"


class V9Packet : public NFPacket {
public:
    V9Packet(CFileReader& fileReader, TemplateMap& templateMap, Aggregator* aggr);
    virtual bool ParseHeader();
    virtual bool ParseBody();

private:
    static const size_t HEADER_SIZE = 20;

    struct {
        uint16_t recordCount;
        uint32_t sysUpTime;
        uint32_t unixSeconds;
        uint32_t seqNumber;
        uint32_t sourceId;
    } headerInfo;

    virtual uint32_t GetDomainID() const {
        return headerInfo.sourceId;
    }

    bool ParseSwitchedTime(uint8_t* rawData, int fieldSize, time_t& switchedTime);
};
