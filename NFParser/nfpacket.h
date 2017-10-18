#pragma once
#include "common.h"
#include "NFStruct.h"
#include "FileReader.h"
#include "FileWriter.h"
#include "StatKeeper.h"

enum FlowVersion {
    NETFLOW_V9 = 9,
    IPFIX = 10
};

class CNFParser;

class NFPacket {
public:
    NFPacket(FlowVersion v, CNFParser* nfParser) : version (v), nfParser(nfParser) {};

    static const size_t VERSION_FIELD_SIZE = 2;
protected:
    uint16_t TEMPLATE_SET_ID;
    FlowVersion version;
    CNFParser* nfParser;

    virtual uint32_t ParseFlowSet();
    virtual int ParseTemplateFlowSet(uint8_t *buffer, size_t dataSize);
    virtual void ParseDataFlowSet(FlowTemplate *nfTemplate, uint8_t *buffer, uint32_t recordCount);
    virtual bool ParseSwitchedTime(uint8_t* rawData, int fieldSize, time_t& switchedTime) = 0;
    virtual bool ParseDateTimeMs(uint8_t* rawData, int fieldSize, time_t& switchedTime);
    //virtual bool ParseDataRecord(uint8_t *rawData, FlowTemplate *nfTemplate, DataRecord* dataRecord);

    // Device identity is called differently in NFv9 and IPFIX (SourceID and DomainID)
    // So we use virtaul function GetDomain here
    virtual uint32_t GetDomainID() const = 0;

    virtual void OutputHeader() = 0;
    virtual void CountStats() = 0;
};
