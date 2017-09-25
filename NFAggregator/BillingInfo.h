#pragma once
#include <unordered_map>
#include <thread>
#include <boost/thread/shared_mutex.hpp>
#include "DBConnect.h"
#include "NetworkClassificator.h"

class BillingInfo
{
public:
    BillingInfo(const std::string &connectStr);
    bool IsBilledSubscriber(uint32_t ipAddr, uint32_t &contractId);
    uint64_t GetNetworkClass(uint32_t ipAddr);
    void RunTests();
    ~BillingInfo();
private:
    typedef std::unordered_map<uint32_t, uint32_t> SubscribersMap;
    static const int refreshPeriodMin = 1; //TODO: change to 5

    std::string connectString;
    DBConnect dbConnect;
    SubscribersMap billedSubscribers; // pairs of IP - contractID
    NetworkClassificator networkClassificator;
    boost::shared_mutex mutex;
    std::thread refreshThread;
    time_t lastRefreshTime;
    bool shutdownFlag;

    void RefreshBilledSubscribers();
    void RefreshThreadFunc();
};

