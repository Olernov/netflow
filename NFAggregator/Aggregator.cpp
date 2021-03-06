#include "Aggregator.h"
#include "LogWriterOtl.h"
#include "Common.h"
#include "AlertSender.h"
#include "otl_utils.h"

extern LogWriterOtl logWriter;
extern AlertSender alertSender;


Aggregator::Aggregator(const Config& config, BillingInfo *bi) :
    config(config),
    stopFlag(false),
    billingInfo(bi)
{
}


void Aggregator::Initialize()
{
    time_t now = time(nullptr);
    lastMapSizeReports.resize(config.dbConnectionsCount, now);
    for (int i = 0; i < config.dbConnectionsCount; ++i) {
        DBConnect* dbConnect = new DBConnect;
        dbConnects.push_back(dbConnect);
        dbConnect->rlogon(config.connectString.c_str());
    }
    for (int i = 0; i < config.dbConnectionsCount; ++i) {
        workerQueues.push_back(new WorkerQueue(workerQueueSize));
        mutexes.push_back(new std::mutex);
        conditionVars.push_back(new std::condition_variable);
        sessionMaps.push_back(new SessionMap);
    }
    exceptionFlags.resize(config.dbConnectionsCount, false);
    for (int i = 0; i < config.dbConnectionsCount; ++i) {
        workerThreads.push_back(new std::thread(&Aggregator::WorkerThreadFunc, this, i));
    }
}


void Aggregator::AddDataRecord(DataRecord* dataRecord)
{
    int initialWorkerIndex = dataRecord->dstIpAddr % config.dbConnectionsCount;
    int workerIndex = initialWorkerIndex;
    bool queueIsFull = false;
    // find first free queue to insert data recrod
    while (!workerQueues[workerIndex]->push(dataRecord)) {
        workerIndex = (workerIndex + 1) % config.dbConnectionsCount;
        if (workerIndex == initialWorkerIndex) {
            // round trip is over
            if (!queueIsFull) {
                logWriter.Write("All worker queues are full. Processing postponed", workerIndex,
                                debug);
            }
            queueIsFull = true;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    conditionVars[workerIndex]->notify_one();
}


void Aggregator::WorkerThreadFunc(int index)
{
    while (!(stopFlag && workerQueues[index]->empty())) {
        MapSizeReportIfNeeded(index);
        ProcessQueue(index);
    }
    logWriter.Write("Shutdown flag set.", index);
    ExportAllSessionsToDB(index);
    logWriter.Write("Thread finish", index);
}


void Aggregator::ProcessQueue(int index)
{
    try {
        DataRecord* dataRecord;
        if (workerQueues[index]->pop(dataRecord)) {
            if (!config.detailedExport) {
                AggregateDataRecord(dataRecord, index);
            }
            else {
                DetailedExportDataRecord(dataRecord, index);
            }
            exceptionFlags[index] = false;
        }
        else {
            if (EjectOneIdleSession(index)) {
                exceptionFlags[index] = false;
            }
            else {
                std::unique_lock<std::mutex> lock(*mutexes[index]);
                conditionVars[index]->wait_for(lock, std::chrono::seconds(3));
            }
        }
    }
    catch(const std::exception& ex) {
        // exception is rethrown from Session.
        exceptionFlags[index] = true;
        logWriter.Write(ex.what(), index);
        alertSender.SendAlert(ex.what());
        dbConnects[index]->reconnect();
    }
}


void Aggregator::AggregateDataRecord(DataRecord* dataRecord, int index)
{
    uint32_t contractId = 0;
    if (billingInfo->IsBilledSubscriber(dataRecord->dstIpAddr, contractId)) {
        uint32_t netClassID = billingInfo->GetNetworkClass(dataRecord->srcIpAddr);
        auto eqRange = sessionMaps[index]->equal_range(dataRecord->dstIpAddr);
        if (eqRange.first == eqRange.second) {
            // not found
            CreateNewSession(dataRecord, contractId, netClassID, index);
        }
        else {
            // one or more sessions for this IP found, try to find appropriate network class
            bool found = false;
            for (auto iter = eqRange.first; iter != eqRange.second; ++iter) {
                if (iter->second.get()->networkClassID == netClassID) {
                    iter->second.get()->UpdateData(dataRecord->inBytes, dataRecord->firstSwitched,
                                                   dataRecord->lastSwitched);
                    found = true;
                    break;
                }
            }
            if (!found) {
                // appropiate network class not found in session map
                CreateNewSession(dataRecord, contractId, netClassID, index);
            }
        }
    }
    delete dataRecord;
}


void Aggregator::CreateNewSession(DataRecord* dataRecord, uint32_t contractId, uint32_t netClassID, int index)
{
    sessionMaps[index]->insert(std::make_pair(dataRecord->dstIpAddr,
        Session_ptr(new Session(
                        dataRecord->dstIpAddr,
                        contractId,
                        netClassID,
                        dataRecord->firstSwitched,
                        dataRecord->lastSwitched,
                        dataRecord->inBytes,
                        config.exportThresholdMb,
                        config.exportThresholdMin,
                        config.sessionEjectPeriodMin,
                        dbConnects[index]))));
}


bool Aggregator::EjectOneIdleSession(int index)
{
    time_t now = time(nullptr);
    for (auto it = sessionMaps[index]->begin(); it != sessionMaps[index]->end(); it++) {
        if (difftime(now, it->second->lastUpdateTime) > config.sessionEjectPeriodMin * 60) {
            it->second->ForceExport();
            sessionMaps[index]->erase(it);
            logWriter.Write("One idle session was ejected. Sessions count: "
                            + std::to_string(sessionMaps[index]->size()), index, debug);
            return true;
        }
    }
    return false;
}


void Aggregator::ExportAllSessionsToDB(int index)
{
    logWriter.Write("Exporting all sessions: " + std::to_string(sessionMaps[index]->size()), index);
    while(std::any_of(sessionMaps[index]->begin(), sessionMaps[index]->end(),
                     [](std::pair<uint32_t, Session_ptr> s) { return s.second.get()->HaveDataToExport(); } )) {
        for (auto& it : *sessionMaps[index]) {
            try {
                it.second->ForceExport();
            }
            catch(const std::runtime_error& ex) {
                logWriter.Write(ex.what(), index);
                alertSender.SendAlert(ex.what());
                dbConnects[index]->reconnect();
            }
        }
    }
    logWriter.Write("All sessions exported.", index);
}


void Aggregator::MapSizeReportIfNeeded(int index)
{
    time_t now = time(nullptr);
    if (difftime(now, lastMapSizeReports[index]) > mapSizeReportPeriodMin * 60) {
        logWriter.Write("Sessions count: " + std::to_string(sessionMaps[index]->size()), index);
        lastMapSizeReports[index] = now;
    }
}


void Aggregator::DetailedExportDataRecord(DataRecord* dataRecord, int index)
{
    try {
        otl_stream dbStream;
        dbStream.open(1,
                "insert into BILLING.NETFLOW_DETAILS (src_ip, src_port, dst_ip, dst_port,"
                " first_switched, last_switched, in_bytes, out_bytes)"
                " values (:src_ip /*bigint*/, :src_port /*long*/, "
                ":dst_ip /*bigint*/, :dst_port /*long*/,"
                " :first_switched /*timestamp*/, :last_switched /*timestamp*/,"
                ":in_bytes /*bigint*/, :out_bytes /*bigint*/)",
                *dbConnects[index]);
            dbStream
                    << static_cast<long long>(dataRecord->srcIpAddr)
                    << static_cast<long>(dataRecord->srcPort)
                    << static_cast<long long>(dataRecord->dstIpAddr)
                    << static_cast<long>(dataRecord->dstPort)
                    << OTL_Utils::Time_t_to_OTL_datetime(dataRecord->firstSwitched)
                    << OTL_Utils::Time_t_to_OTL_datetime(dataRecord->lastSwitched)
                    << static_cast<long long>(dataRecord->inBytes)
                    << static_cast<long long>(dataRecord->outBytes);
        dbStream.close();
    }
    catch(const otl_exception& ex) {
        throw std::runtime_error("**** DB ERROR while detailed export ****"
                                 + crlf + OTL_Utils::OtlExceptionToText(ex));
    }
}


bool Aggregator::CanContinueProcessing(std::string &descr)
{
    for (int i = 0; i < config.dbConnectionsCount; ++i) {
        if (exceptionFlags[i]) {
            descr = "Exception(s) in thread #" + std::to_string(i);
            return false;
        }
        if (sessionMaps[i]->size() > maxMapSize) {
            std::stringstream ss;
            ss << "Session map #" << i << " size (" << sessionMaps[i]->size()
                    << ") exceeded maximum allowed (" << std::to_string(maxMapSize) << ")";
            descr = ss.str();
            return false;
        }
    }
    return true;
}


void Aggregator::Stop()
{
    stopFlag = true;
    for (auto it : workerThreads) {
        it->join();
    }
}

Aggregator::~Aggregator()
{
    for (auto it : workerQueues) {
        delete it;
    }
    for (auto it : dbConnects) {
        it->commit();
        it->logoff();
        delete it;
    }
    for (auto it : sessionMaps) {
        delete it;
    }
}

