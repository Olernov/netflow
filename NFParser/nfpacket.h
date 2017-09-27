#pragma once
#include "common.h"
#include "FileReader.h"
#include "FileWriter.h"
#include "StatKeeper.h"

enum FlowVersion {
    NETFLOW_V9 = 9,
    IPFIX = 10
};

class CNFParser;

struct NFPacket {
    NFPacket(FlowVersion v, CNFParser* nfParser) : version (v), nfParser(nfParser) {};

    static const size_t HEADER_SIZE = 20;
    static const size_t VERSION_FIELD_SIZE = 2;

    FlowVersion version;
    CNFParser* nfParser;

    virtual bool ParseHeader() = 0;
    virtual bool ParseBody() = 0;
    virtual void OutputHeader() = 0;
    virtual void CountStats() = 0;
};
