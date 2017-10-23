#include "IpFixPacket.h"

IpFixPacket::IpFixPacket(CNFParser* nfParser) :
    NFPacket(IPFIX, nfParser)
{}

bool IpFixPacket::ParseHeader()
{
    // TODO:
    return true;
}

bool IpFixPacket::ParseBody()
{
    // TODO:
    return true;
}

void IpFixPacket::OutputHeader()
{
    // TODO:
}

void IpFixPacket::CountStats()
{
    // TODO:
}
