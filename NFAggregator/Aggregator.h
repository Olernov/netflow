#pragma once
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <boost/lockfree/queue.hpp>
#include "DBConnect.h"
#include "DataRecord.h"
#include "BillingInfo.h"
#include "Config.h"
#include "Session.h"

typedef boost::lockfree::queue<DataRecord*, boost::lockfree::fixed_sized<true>> WorkerQueue;
typedef std::unordered_multimap<uint32_t, Session_ptr> SessionMap;

class Aggregator
{
public:
    Aggregator(const Config& config, BillingInfo* billingInfo);
    void Initialize();
    void AddDataRecord(DataRecord* dataRecord);
    void Stop();
    ~Aggregator();

private:
    static const int workerQueueSize = 5000;
    static const  int mapSizeReportPeriodMin = 5;

    const Config &config;
    short dbConnectCnt;
    bool stopFlag;
    std::vector<DBConnect*> dbConnects;
    std::vector<WorkerQueue*> workerQueues;
    std::vector<std::thread*> workerThreads;
    std::vector<std::mutex*> mutexes;
    std::vector<std::condition_variable*> conditionVars;
    std::vector<SessionMap*> sessionMaps;
    BillingInfo* billingInfo;
    std::string exceptionText;
    std::vector<time_t> lastMapSizeReports;

    void WorkerThreadFunc(int index);
    void ProcessQueue(int index);
    void ProcessDataRecord(DataRecord* dataRecord, int index);
    void CreateNewSession(DataRecord* dataRecord, uint32_t contractId,
                          uint32_t netClassID, int index);
    void ExportAllSessionsToDB(int index);
    bool EjectOneIdleSession(int index);
    void MapSizeReportIfNeeded(int index);
};
