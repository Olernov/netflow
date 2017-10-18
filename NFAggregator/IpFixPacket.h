#pragma once
#include "nfpacket.h"
#include "FileReader.h"
#include "Aggregator.h"

class IpFixPacket : public NFPacket
{
public:
    IpFixPacket(CFileReader& fr, TemplateMap& tm, Aggregator* aggr);
    virtual bool ParseHeader();
    virtual bool ParseBody();

private:
    static const size_t HEADER_SIZE = 16;

    struct {
        uint16_t length;
        uint32_t exportTime;
        uint32_t sequenceNumber;
        uint32_t domainId;
    } headerInfo;
    bool ParseSwitchedTime(uint8_t* rawData, int fieldSize, time_t& switchedTime);

    virtual uint32_t GetDomainID() const {
        return headerInfo.domainId;
    }
};
