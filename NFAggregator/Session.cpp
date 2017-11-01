#include "otl_utils.h"
#include "Session.h"
#include "LogWriterOtl.h"
#include "Common.h"

extern LogWriterOtl logWriter;

Session::Session(uint32_t ipAddress,
        uint32_t contractID,
        uint32_t networkClassID,
        time_t firstSwitched,
        time_t lastSwitched,
        uint64_t inBytes,
        long exportThresholdMb,
        long exportThresholdMin,
        long sessionEjectPeriodMin,
        DBConnect *db) :
    ipAddress(ipAddress),
    contractID(contractID),
    networkClassID(networkClassID),
    firstSwitched(firstSwitched),
    lastSwitched(lastSwitched),
    inBytesAggregated(inBytes),
    inBytesExported(0),
    lastUpdateTime(time(nullptr)),
    lastExportTime(notInitialized),
    exportThresholdMb(exportThresholdMb),
    exportThresholdMin(exportThresholdMin),
    sessionEjectPeriodMin(sessionEjectPeriodMin),
    dbConnect(db)
{
    ExportIfNecessary();
}


void Session::UpdateData(uint64_t inBytesIncrease, time_t newFirstSwitched, time_t newLastSwitched)
{
    inBytesAggregated += inBytesIncrease;
    if (firstSwitched == notInitialized || newFirstSwitched < firstSwitched) {
        firstSwitched = newFirstSwitched;
    }
    if (lastSwitched == notInitialized || newLastSwitched > lastSwitched) {
        lastSwitched = newLastSwitched;
    }
    lastUpdateTime = time(nullptr);
    ExportIfNecessary();
}


void Session::ExportIfNecessary()
{
    if (inBytesAggregated >= exportThresholdMb * megabyteSizeInBytes ||
            difftime(lastSwitched, firstSwitched) >= exportThresholdMin*60) {
        ForceExport();
    }
}


void Session::ForceExport()
{
    if (HaveDataToExport()) {
        try {
            otl_stream dbStream;
            dbStream.open(1,
                    "insert into BILLING.NETFLOW (ip_address, contract_id, networkclass_id,"
                    " first_switched, last_switched, in_bytes, export_time, status)"
                    " values (:ip /*bigint*/, :contract_id /*bigint*/, :netclass /*bigint*/,"
                    " :first_switched /*timestamp*/, :last_switched /*timestamp*/,"
                    ":in_bytes /*bigint*/, :export_time /*timestamp*/, :status /*long*/)",
                    *dbConnect);
                dbStream
                        << static_cast<long long>(ipAddress)
                        << static_cast<long long>(contractID)
                        << static_cast<long long>(networkClassID)
                        << OTL_Utils::Time_t_to_OTL_datetime(firstSwitched)
                        << OTL_Utils::Time_t_to_OTL_datetime(lastSwitched)
                        << static_cast<long long>(inBytesAggregated)
                        << OTL_Utils::Time_t_to_OTL_datetime(time(nullptr))
                        << defaultExportedRecordStatus;
            dbStream.close();

            inBytesExported += inBytesAggregated;
            inBytesAggregated = 0;
            firstSwitched = notInitialized;
            lastSwitched = notInitialized;
            lastExportTime = time(nullptr);
        }
        catch(const otl_exception& ex) {
            throw std::runtime_error("**** DB ERROR while exporting ****"
                                     + crlf + OTL_Utils::OtlExceptionToText(ex));
        }
    }
}
