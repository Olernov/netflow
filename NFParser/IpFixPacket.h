#pragma once
#include "nfpacket.h"

class CNFParser;

struct IpFixPacket : public NFPacket
{
    IpFixPacket(CNFParser* nfParser);
    uint16_t length;
    uint32_t exportTime;
    uint32_t sequenceNumber;
    uint32_t domainId;

    virtual bool ParseHeader();
    virtual bool ParseBody();
    virtual void OutputHeader();
    virtual void CountStats();
};
