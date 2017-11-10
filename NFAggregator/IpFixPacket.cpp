#include "IpFixPacket.h"

IpFixPacket::IpFixPacket(CFileReader& fr, TemplateMap& tm, Aggregator* aggr) :
     NFPacket(IPFIX, fr, tm, aggr)
{}

bool IpFixPacket::ParseHeader()
{
    uint8_t* buffer;
    const size_t bytesToRead = HEADER_SIZE - VERSION_FIELD_SIZE;
    size_t bytesRead = fileReader.ReadData(&buffer, bytesToRead);
    if (bytesRead != bytesToRead) {
        return false;
    }
    bytesProcessed += bytesRead;

    size_t bufferPos = 0;
    headerInfo.length = ntohs (*((u_short*)&(buffer[bufferPos])));
    bufferPos += 2;

    headerInfo.exportTime = ntohl (*((u_long*)&(buffer[bufferPos])));
    bufferPos += 4;

    headerInfo.sequenceNumber = ntohl (*((u_long*)&(buffer[bufferPos])));
    bufferPos += 4;

    headerInfo.domainId = ntohl (*((u_long*)&(buffer[bufferPos])));
    bufferPos += 4;
    return true;
}

bool IpFixPacket::ParseBody()
{
    while(bytesProcessed < headerInfo.length) {
        if (ParseFlowSet() < 0) {
            return false;
        }
    }
    return true;
}

bool IpFixPacket::ParseSwitchedTime(uint8_t* rawData, int fieldSize, time_t& switchedTime)
{
    // unable to parse switched time for IPFIX since we don't have sysUpTime in packet header
    return false;
}
