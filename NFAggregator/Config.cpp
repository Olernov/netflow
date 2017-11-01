#include <boost/filesystem.hpp>
#include <sstream>
#include "Config.h"
#include "Common.h"

using namespace boost;

Config::Config() :
    cdrExtension(".nas"),
    dbConnectionsCount(8),
    exportThresholdMb(10),
    exportThresholdMin(60),
    sessionEjectPeriodMin(30),
    noCdrAlertPeriodMin(15),
    logLevel(notice),
    detailedExport(false)
{
}


Config::Config(std::ifstream& configStream) :
    Config()
{
    ReadConfigFile(configStream);
}


void Config::ReadConfigFile(std::ifstream& configStream)
{
    std::string line;
    while (getline(configStream, line))
	{
		size_t pos = line.find_first_not_of(" \t\r\n");
        if (pos != std::string::npos) {
            if (line[pos] == '#' || line[pos] == '\0') {
				continue;
            }
        }
		size_t delim_pos = line.find_first_of(" \t=", pos);
        std::string option_name;
        if (delim_pos != std::string::npos) {
			option_name = line.substr(pos, delim_pos - pos);
        }
        else {
			option_name = line;
        }
		
        std::transform(option_name.begin(), option_name.end(), option_name.begin(), ::toupper);

		size_t value_pos = line.find_first_not_of(" \t=", delim_pos);
        std::string option_value;
        if (value_pos != std::string::npos) {
			option_value = line.substr(value_pos);
			size_t comment_pos = option_value.find_first_of(" \t#");
            if (comment_pos != std::string::npos)
				option_value = option_value.substr(0, comment_pos);
		}

        if (option_name == connectStringParamName) {
            connectString = option_value;
        }
        else if (option_name == inputDirParamName) {
            inputDirs.push_back(option_value);
        }
        else if (option_name == archiveDirParamName) {
            archiveDirs.push_back(option_value);
        }
        else if (option_name == logDirParamName) {
            logDirs.push_back(option_value);
        }
        else if (option_name == cdrExtensionParamName) {
            cdrExtension = option_value;
        }
        else if (option_name == dbConectionsCountParamName) {
            dbConnectionsCount = ParseULongValue(option_name, option_value);
        }
        else if (option_name == exportThresholdMbParamName) {
            exportThresholdMb = ParseULongValue(option_name, option_value);
        }
        else if (option_name == exportThresholdMinParamName) {
            exportThresholdMin = ParseULongValue(option_name, option_value);
        }
        else if (option_name == sessionEjectPeriodParamName) {
            sessionEjectPeriodMin = ParseULongValue(option_name, option_value);
        }
        else if (option_name == logLevelParamName) {
            if (option_value == "error") {
                logLevel = error;
            }
            else if (option_value == "notice") {
                logLevel = notice;
            }
            else if (option_value == "debug") {
                logLevel = debug;
            }
            else {
                throw std::runtime_error("Wrong value passed for " + option_name + ".");
            }
        }
        else if (option_name == noCdrAlertPeriodParamName) {
            noCdrAlertPeriodMin = ParseULongValue(option_name, option_value);
        }
        else if (!option_name.empty()){
            throw std::runtime_error("Unknown parameter " + option_name + " found");
        }
	}	
}


unsigned long Config::ParseULongValue(const std::string& name, const std::string& value)
{
    try {
        return std::stoul(value);
    }
    catch(const std::invalid_argument&) {
        throw std::runtime_error("Wrong value given for numeric config parameter " + name);
    }
}

void Config::ValidateParams()
{
    if (connectString.empty()) {
        throw std::runtime_error(connectStringParamName + " parameter is not set.");
    }
    if (inputDirs.empty()) {
        throw std::runtime_error(inputDirParamName + " parameter is not set.");
    }
    if (archiveDirs.size() != inputDirs.size()) {
        throw std::runtime_error("Count of INPUT_DIRs must be equal to the count of ARCHIVE_DIRs.");
    }
    if (logDirs.size() != inputDirs.size()) {
        throw std::runtime_error("Count of INPUT_DIRs must be equal to the count of LOG_DIRs.");
    }

    for (auto d : inputDirs) {
        ValidateDirectory(d);
    }
    for (auto d : archiveDirs) {
        ValidateDirectory(d);
    }
    for (auto d : logDirs) {
        ValidateDirectory(d);
    }

    if (!(dbConnectionsCount >= minThreadCount && dbConnectionsCount <= maxThreadCount)) {
        throw std::runtime_error(dbConectionsCountParamName + " must have value from " +
                                 std::to_string(minThreadCount) + " to " + std::to_string(maxThreadCount));
    }
}


void Config::ValidateDirectory(const std::string& dir)
{
    filesystem::path path(dir);
    if (!filesystem::exists(path)) {
        throw std::runtime_error(std::string("Input directory ") + dir + " does not exist");
    }
    if (!filesystem::is_directory(path)) {
        throw std::runtime_error(dir + " is not a directory");
    }
}

std::string Config::DumpAllSettings()
{
    std::stringstream ss;
    ss << connectStringParamName << ": " << connectString << std::endl;
    for (auto d : inputDirs) {
        ss << inputDirParamName << ": " << d << std::endl;
    }
    for (auto d : archiveDirs) {
        ss << archiveDirParamName << ": " << d << std::endl;
    }
    for (auto d : logDirs) {
        ss << logDirParamName << ": " << d << std::endl;
    }
    ss  << cdrExtensionParamName << ": " << cdrExtension << std::endl
        << exportThresholdMbParamName << ": " << std::to_string(exportThresholdMb) << std::endl
        << exportThresholdMinParamName << ": " << std::to_string(exportThresholdMin) << std::endl
        << sessionEjectPeriodParamName << ": " << std::to_string(sessionEjectPeriodMin)  << std::endl
        << logLevelParamName << ": "
            << (logLevel == error ? "error" : (logLevel == debug ? "debug" : "notice"))  << std::endl
        << noCdrAlertPeriodParamName << ": " << std::to_string(noCdrAlertPeriodMin) << std::endl
        << "detailed export: " << (detailedExport ? "ON" : "OFF") << std::endl;
    return ss.str();
}

