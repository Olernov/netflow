#include "v9packet.h"

extern void UnixTimeToStr(
    uint32_t p_dwUnixTime,
    char *m_pmcOutputStr,
    size_t p_stMaxChars);


V9Packet::V9Packet(CFileReader& fr, TemplateMap& tm, Aggregator *aggr) :
    NFPacket(NETFLOW_V9, fr, tm, aggr)
{}


bool V9Packet::ParseHeader()
{
    uint8_t* buffer;
    const size_t bytesToRead = HEADER_SIZE - VERSION_FIELD_SIZE;
    size_t bytesRead = fileReader.ReadData(&buffer, bytesToRead);
    if (bytesRead != bytesToRead) {
        return false;
    }
    bytesProcessed += bytesRead;

    size_t bufferPos = 0;
    headerInfo.recordCount = ntohs (*((u_short*)&(buffer[bufferPos])));
    bufferPos += 2;

    headerInfo.sysUpTime = ntohl (*((u_long*)&(buffer[bufferPos])));
    bufferPos += 4;

    headerInfo.unixSeconds = ntohl (*((u_long*)&(buffer[bufferPos])));
    bufferPos += 4;

    headerInfo.seqNumber = ntohl (*((u_long*)&(buffer[bufferPos])));
    bufferPos += 4;

    headerInfo.sourceId = ntohl (*((u_long*)&(buffer[bufferPos])));
    return true;
}


bool V9Packet::ParseBody()
{
    uint32_t processedCount = 0;
    while (processedCount < headerInfo.recordCount) {
        uint32_t processedFromFlowset = ParseFlowSet();
        if (processedFromFlowset == 0) {
            break;
        }
        if (processedFromFlowset == -1) {
            return false;
        }
        processedCount += processedFromFlowset;
    }
    return true;
}


bool V9Packet::ParseSwitchedTime(uint8_t* rawData, int fieldSize, time_t& switchedTime)
{
    uint32_t switchedTimeMs;
    if (!ReadInteger(rawData, fieldSize, switchedTimeMs)) {
        return false;
    }

    int timeDeltaMs = switchedTimeMs - headerInfo.sysUpTime;
    int milliSecPart = timeDeltaMs % 1000;
    switchedTime = headerInfo.unixSeconds + timeDeltaMs/1000;
    if (milliSecPart < 0) {
        switchedTime--;
    }
    return true;
}
