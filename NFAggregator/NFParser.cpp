#include <memory.h>
#include "NFParser.h"
#include "FileReader.h"

CNFParser::CNFParser()
{
    ResetCounters();
}

void CNFParser::Initialize(Aggregator *aggr)
{
    aggregator = aggr;
}

bool CNFParser::ProcessNextExportPacket(CFileReader &fileReader)
{
    uint8_t *buffer;
    size_t stBytesRead = fileReader.ReadData(&buffer, NFPacket::VERSION_FIELD_SIZE);
    if (stBytesRead != NFPacket::VERSION_FIELD_SIZE) {
        return false;
    }
    uint16_t version = ntohs (*((u_short*)buffer));
    if (version != NETFLOW_V9  && version != IPFIX) {
        // TODO: signal ERROR!
        printf("Error: invalid version number: %u\r\n", version);
       return false;
    }

    NFPacket* nfPacket = nullptr;
    if (version == NETFLOW_V9) {
        nfPacket = new V9Packet(fileReader, m_mapTemplates, aggregator);
    }
    else if (version == IPFIX) {
        nfPacket = new IpFixPacket(fileReader, m_mapTemplates, aggregator);
    }
    if (!nfPacket->ParseHeader()) {
        // TODO: signal ERROR!
        return false;
    }

    bool parseRes = nfPacket->ParseBody();
    dataRecordsCount += nfPacket->GetDataRecordsCount();
    templatesCount += nfPacket->GetTemplatesCount();
    delete nfPacket;
    return parseRes;
}

void CNFParser::ResetCounters()
{
    dataRecordsCount = 0;
    templatesCount = 0;
}
