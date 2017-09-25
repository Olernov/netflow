#pragma once
#include <memory>
#include "BillingInfo.h"

class Session
{
public:
    Session(uint32_t ipAddress,
        uint32_t contractID,
        uint32_t networkClassID,
        time_t firstSwitched,
        time_t lastSwitched,
        uint64_t inBytes,
        long volumeExportThresholdMb,
        long sessionEjectPeriodMin,
        DBConnect* db);
    uint32_t ipAddress;
    uint32_t contractID;
    uint32_t networkClassID;
    time_t firstSwitched;
    time_t lastSwitched;
    uint64_t inBytesAggregated;
    uint64_t inBytesExported;
    time_t lastUpdateTime;
    time_t lastExportTime;

    void UpdateData(uint64_t inBytesIncrease, time_t newFirstSwitched, time_t newLastSwitched);
    void ForceExport();
    inline bool HaveDataToExport() const
        { return inBytesAggregated>0 || lastSwitched>firstSwitched; }
private:
    const long megabyteSizeInBytes = 1024*1024;
    const long volumeExportThresholdMb;
    const long sessionEjectPeriodMin;
    const long defaultExportedRecordStatus = 0;

    DBConnect* dbConnect;

    void ExportIfNecessary();
};

typedef std::shared_ptr<Session> Session_ptr;
