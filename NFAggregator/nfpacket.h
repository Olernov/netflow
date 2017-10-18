#pragma once
#include "FileReader.h"
#include "Aggregator.h"
#include "DataRecord.h"
#include "NFStruct.h"

enum FlowVersion {
    NETFLOW_V9 = 9,
    IPFIX = 10
};



class NFPacket {
public:
    NFPacket(FlowVersion v, CFileReader& fr, TemplateMap& tm, Aggregator* aggr);

    virtual ~NFPacket() {};
    virtual bool ParseHeader() = 0;
    virtual bool ParseBody() = 0;

    inline uint32_t GetDataRecordsCount() const { return dataRecordsCount; }
    inline uint32_t GetTemplatesCount() const { return templatesCount; }

    static const size_t VERSION_FIELD_SIZE = 2;
protected:
    uint16_t TEMPLATE_SET_ID;
    FlowVersion version;
    CFileReader& fileReader;
    Aggregator* aggregator;
    TemplateMap& templateMap;
    uint32_t dataRecordsCount;
    uint32_t templatesCount;
    uint32_t bytesProcessed;

    virtual int32_t ParseFlowSet();
    virtual int ParseTemplateFlowSet(uint8_t *buffer, size_t dataSize);
    virtual void ParseDataFlowSet(FlowTemplate *nfTemplate, uint8_t *buffer, uint32_t recordCount);
    virtual bool ParseSwitchedTime(uint8_t* rawData, int fieldSize, time_t& switchedTime) = 0;
    virtual bool ParseDateTimeMs(uint8_t* rawData, int fieldSize, time_t& switchedTime);
    virtual bool ParseDataRecord(uint8_t *rawData, FlowTemplate *nfTemplate, DataRecord* dataRecord);

    // Device identity is called differently in NFv9 and IPFIX (SourceID and DomainID)
    // So we use virtual function GetDomain here
    virtual uint32_t GetDomainID() const = 0;

    template<typename T>
    bool ReadInteger(uint8_t* rawData, int fieldSize, T& value) {
        if (fieldSize > sizeof(value)) {
            return false;
        }
        value = 0;
        for (int i = 0; i < fieldSize; ++i) {
            value <<= 8;
            value |= *rawData;
            ++rawData;
        }
        return true;
    }
};
