#pragma once
#include <boost/filesystem.hpp>
#include "BillingInfo.h"
#include "Aggregator.h"
#include "NFParser.h"

using namespace boost;

class Config;


class MainLoopController
{
public:
    MainLoopController(const Config& config);

    void Run();
    void Stop();
private:
    const Config& config;
    typedef std::vector<filesystem::path> fileList;
    const uint32_t fileReaderChunkSize = 0x1000000;
    const size_t maxAlertMessageLen = 2000;
    std::string lastAlertMessage;
    time_t lastAlertTime;
    bool shutdownFlag;
    BillingInfo billingInfo;
    Aggregator aggregator;
    CNFParser nfParser;

    void ConstructSortedFileList(const std::string& inputDir,
                                 const std::string &cdrExtension, fileList &sourceFiles);
};


