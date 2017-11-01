#pragma once
#include <stdio.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <algorithm>
#include "LogWriterOtl.h"

struct Config
{
public:
    Config();
    Config(std::ifstream& cfgStream);

    void ReadConfigFile(std::ifstream& cfgStream);
    void ValidateParams();
    std::string DumpAllSettings();
    std::string connectString;
    std::vector<std::string> inputDirs;
    std::vector<std::string> archiveDirs;
    std::vector<std::string> logDirs;
    std::string cdrExtension;
    unsigned short dbConnectionsCount;
    unsigned long homePlmnID;
    unsigned long exportThresholdMb;
    unsigned long exportThresholdMin;
    unsigned long sessionEjectPeriodMin;
    unsigned long noCdrAlertPeriodMin;
    LogLevel logLevel;
    bool detailedExport;
private:
    const std::string connectStringParamName = "CONNECT_STRING";
    const std::string inputDirParamName = "INPUT_DIR";
    const std::string archiveDirParamName = "ARCHIVE_DIR";
    const std::string logDirParamName = "LOG_DIR";
    const std::string cdrExtensionParamName = "CDR_FILES_EXTENSION";
    const std::string dbConectionsCountParamName = "DB_CONNECTIONS_COUNT";
    const std::string exportThresholdMbParamName = "EXPORT_THRESHOLD_MB";
    const std::string exportThresholdMinParamName = "EXPORT_THRESHOLD_MIN";
    const std::string sessionEjectPeriodParamName = "SESSION_EJECT_PERIOD";
    const std::string noCdrAlertPeriodParamName = "NO_CDR_ALERT_PERIOD_MIN";
    const std::string logLevelParamName = "LOG_LEVEL";
    const int minThreadCount = 1;
    const int maxThreadCount = 32;
    unsigned long ParseULongValue(const std::string& name, const std::string& value);
    void ValidateDirectory(const std::string& dir);
};
