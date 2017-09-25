#pragma once
#include <mutex>
#include <unordered_map>
#include "DBConnect.h"


class AlertSender
{
public:
    AlertSender(const std::string &moduleName);
    void Initialize(const std::string &connectString);
    bool SendAlert(const std::string& text);
    ~AlertSender();
private:
    // interval after which alert with the same text will be sent repeatedly
    static const int messageRepeatTimeoutMin = 15;

    DBConnect dbConnect;
    std::string moduleName;
    std::mutex mutex;
    std::unordered_map<std::string, time_t> lastSends;
};
