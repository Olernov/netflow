#include "BillingInfo.h"
#include "LogWriterOtl.h"
#include "otl_utils.h"
#include "Common.h"
#include "AlertSender.h"

extern LogWriterOtl logWriter;
extern AlertSender alertSender;

BillingInfo::BillingInfo(const std::string &connectStr) :
    connectString(connectStr),
    networkClassificator(dbConnect),
    lastRefreshTime(notInitialized),
    shutdownFlag(false)
{
    logWriter << "Initializing BillingInfo ...";
    dbConnect.rlogon(connectString.c_str());
    RefreshBilledSubscribers();
    networkClassificator.RefreshClassesFromDB();
    lastRefreshTime = time(nullptr);
    refreshThread = std::thread(&BillingInfo::RefreshThreadFunc, this);
}


bool BillingInfo::IsBilledSubscriber(uint32_t ipAddr, uint32_t& contractId)
{
    // get shared access
    boost::shared_lock<boost::shared_mutex> lock(mutex);
    auto iter = billedSubscribers.find(ipAddr);
    if (iter != billedSubscribers.end()) {
        contractId = iter->second;
        return true;
    }
    else {
        return false;
    }
}


uint64_t BillingInfo::GetNetworkClass(uint32_t ipAddr)
{

    return networkClassificator.GetIpClass(ipAddr);
}

void BillingInfo::RefreshBilledSubscribers()
{
    logWriter << "RefreshBilledSubscribers started ...";

    // for performance purposes read actual info into new structure and then
    // substitute old one with new in a synchronized section (see below)
    SubscribersMap newBilledSubscribers;

    otl_stream dbStream;
    dbStream.open(1000, "select * from BILLING.VAGGR_BILLED_SUBSCRIBERS", dbConnect);
    while(!dbStream.eof()) {
        uint32_t startIp, endIp, contractId;
        dbStream >> startIp >> endIp >> contractId;
        for (int nextIp = startIp; nextIp <= endIp; ++nextIp) {
            newBilledSubscribers.insert(std::make_pair(nextIp, contractId));
        }
    }
    dbStream.close();
    // get upgradable access
    boost::upgrade_lock<boost::shared_mutex> lock(mutex);
    // get exclusive access
    boost::upgrade_to_unique_lock<boost::shared_mutex> uniqueLock(lock);
    // now we have exclusive access, substitute old map with new
    billedSubscribers = newBilledSubscribers;

    logWriter << "RefreshBilledSubscribers success. Billed IP count: "
             + std::to_string(billedSubscribers.size());
}


void BillingInfo::RefreshThreadFunc()
{
    while(!shutdownFlag) {
        if (difftime(time(nullptr), lastRefreshTime) > refreshPeriodMin * 60) {
            try {
                RefreshBilledSubscribers();
                networkClassificator.RefreshClassesFromDB();
            }
            catch(otl_exception& ex) {
                std::string message = "Refresh billing info failed: " + OTL_Utils::OtlExceptionToText(ex);
                logWriter << message;
                alertSender.SendAlert(message);
                dbConnect.reconnect();
            }
            lastRefreshTime = time(nullptr);
        }
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}


void BillingInfo::RunTests()
{
    uint32_t contractID;
    assert(IsBilledSubscriber(1410491652, contractID));
    assert(contractID == 884693186);
    assert(IsBilledSubscriber(1410491655, contractID));
    assert(contractID == 884693186);
    assert(IsBilledSubscriber(1410491656, contractID) == false);
    assert(IsBilledSubscriber(1317701120, contractID));
    assert(contractID == 212493443);
    assert(IsBilledSubscriber(1317701200, contractID));
    assert(contractID == 212493443);
    assert(IsBilledSubscriber(1317703922, contractID));
    assert(contractID == 194467500);
    assert(IsBilledSubscriber(1317703925, contractID) == false);
    networkClassificator.RunTests();
}


BillingInfo::~BillingInfo()
{
    shutdownFlag = true;
    if (refreshThread.joinable()) {
        refreshThread.join();
    }
    dbConnect.logoff();
}
