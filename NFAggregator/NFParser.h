#pragma once
#include "Common.h"
#include "DataRecord.h"
#include "Aggregator.h"
#include "nfpacket.h"
#include "v9packet.h"
#include "IpFixPacket.h"
#include "NFStruct.h"
#include "FileReader.h"

class CNFParser
{
public:
    CNFParser();
    void Initialize(Aggregator* aggr);
    bool ProcessNextExportPacket(CFileReader& fileReader, std::string &errorDescr);
    void ResetCounters();
    inline uint32_t GetDataRecordsCount() const { return dataRecordsCount; }
    inline uint32_t GetTemplatesCount() const { return templatesCount; }
private:
    Aggregator* aggregator;
    TemplateMap m_mapTemplates;
    uint32_t dataRecordsCount;
    uint32_t templatesCount;
};
