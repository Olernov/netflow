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
    uint32_t processedFromFlowset = ParseFlowSet();
    return true;
}

bool IpFixPacket::ParseSwitchedTime(uint8_t* rawData, int fieldSize, time_t& switchedTime)
{
    // TODO:
    //    uint32_t switchedTimeMs;
//    if (!ReadInteger(rawData, fieldSize, switchedTimeMs)) {
//        return false;
//    }

//    int timeDeltaMs = switchedTimeMs - sysUpTime;
//    int milliSecPart = timeDeltaMs % 1000;
//    switchedTime = unixSeconds + timeDeltaMs/1000;
//    if (milliSecPart < 0) {
//        switchedTime--;
//    }
    return true;
}
