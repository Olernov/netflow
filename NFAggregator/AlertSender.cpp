#include "AlertSender.h"
#include "LogWriterOtl.h"
#include "otl_utils.h"

extern LogWriterOtl logWriter;

AlertSender::AlertSender(const std::string &moduleName) :
    moduleName(moduleName)
{}


void AlertSender::Initialize(const std::string &connectString)
{
    dbConnect.rlogon(connectString.c_str());
}


bool AlertSender::SendAlert(const std::string& text)
{
    std::unique_lock<std::mutex> lock(mutex);
    auto it = lastSends.find(text);
    if (it == lastSends.end() || difftime(time(nullptr), it->second) / 60 > messageRepeatTimeoutMin) {
        otl_stream dbStream;
        try {
            dbStream.open(1, "call BILLING.SendAlert(:module /*char[100],in*/, :text /*char[2000],in*/)",
                          dbConnect);
            dbStream << moduleName << text;
            if (it == lastSends.end()) {
                lastSends.insert(std::make_pair(text, time(nullptr)));
            }
            else {
                it->second = time(nullptr);
            }
        }
        catch(otl_exception& ex) {
            logWriter << "SendAlert failed: " + OTL_Utils::OtlExceptionToText(ex);
            dbConnect.reconnect();
            return false;
        }
    }
    return true;
}

AlertSender::~AlertSender()
{
    dbConnect.logoff();
}
