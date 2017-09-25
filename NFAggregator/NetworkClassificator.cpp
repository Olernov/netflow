#include <cassert>
#include "NetworkClassificator.h"
#include "LogWriterOtl.h"

extern LogWriterOtl logWriter;

NetworkClassificator::NetworkClassificator(DBConnect &db) :
    binarySearchThreshold(defaultBinarySearchThreshold),
    dbConnect(db)
{
}


void NetworkClassificator::RefreshClassesFromDB()
{
    logWriter << "NetworkClassificator: RefreshClassesFromDB started ...";

    // for performance purposes read actual info into new structures and then
    // substitute old one with new in a synchronized section (see below)
    std::vector<uint64_t> newNetworkVolumes;
    std::vector<NetClassVector> newNetClassTable;

    otl_stream dbStream;
    dbStream.open(100, "select volume /*long*/, start_ip /*long*/, networkclass_id /*bigint*/ "
                       " from BILLING.VAGGR_NETWORK_CLASSES"
                       " order by volume", dbConnect);
    int networkCount = 0;
    while(!dbStream.eof()) {
        long startIp, networkClassId;
        long long volume;
        dbStream >> volume >> startIp >> networkClassId;
        if (newNetworkVolumes.empty() ||
                newNetworkVolumes[newNetworkVolumes.size() - 1] != static_cast<uint64_t>(volume)) {
            newNetworkVolumes.push_back(volume);
            newNetClassTable.push_back(NetClassVector());
        }
        newNetClassTable[newNetClassTable.size() - 1].push_back(std::make_pair(startIp, networkClassId));
        ++networkCount;
    }
    dbStream.close();

    // get upgradable access
    boost::upgrade_lock<boost::shared_mutex> lock(mutex);
    // get exclusive access
    boost::upgrade_to_unique_lock<boost::shared_mutex> uniqueLock(lock);
    // now we have exclusive access, substitute old structures with new
    networkVolumes = newNetworkVolumes;
    netClassTable = newNetClassTable;

    logWriter << "NetworkClassificator: RefreshClassesFromDB success. Distinct network volumes: "
        + std::to_string(networkVolumes.size()) + ". Total networks: " + std::to_string(networkCount);
}



uint32_t NetworkClassificator::GetIpClass(uint32_t ipAddress)
{
    // get shared access
    boost::shared_lock<boost::shared_mutex> lock(mutex);
    uint32_t netClass;
    for (size_t row = 0; row < networkVolumes.size(); ++row) {
        if (netClassTable[row].size() >= binarySearchThreshold) {
            netClass = BinarySearchForNetwork(ipAddress, row, 0 , netClassTable[row].size() - 1);
        }
        else {
            netClass = FullScanForNetwork(ipAddress, row);
        }
        if (netClass > 0) {
            return netClass;
        }
    }
    return 0;
}


uint32_t NetworkClassificator::BinarySearchForNetwork(uint32_t ipAddress, size_t rowIndex,
                                                      size_t from, size_t to)
{
    size_t middle = from + (to - from)/ 2;
    uint32_t networkStartIp = netClassTable[rowIndex][middle].first;
    if ((networkStartIp <= ipAddress) && (ipAddress < networkStartIp + networkVolumes[rowIndex])) {
        return netClassTable[rowIndex][middle].second;
    }

    if (ipAddress < networkStartIp) {
        if (from < middle) {
            return BinarySearchForNetwork(ipAddress, rowIndex, from, middle - 1);
        }
        else {
            return 0;
        }
    }
    else {
        if (to > middle) {
            return BinarySearchForNetwork(ipAddress, rowIndex, middle + 1 , to);
        }
        else {
            return 0;
        }
    }

    return 0;
}


uint32_t NetworkClassificator::FullScanForNetwork(uint32_t ipAddress, size_t rowIndex)
{
    for(auto it : netClassTable[rowIndex]) {
        if ((it.first <= ipAddress) && (ipAddress < it.first + networkVolumes[rowIndex])) {
            return it.second;
        }
    }
    return 0;
}



void NetworkClassificator::RunTests()
{
    binarySearchThreshold = 1000; // disable binary search to force full scan
    networkVolumes.clear();
    netClassTable.clear();
    networkVolumes = {1, 4, 8, 64};
    netClassTable = {{{20, 1}, {30, 2}, {40, 3}, {50, 4}, {60, 5}}, // volume == 1
                     {{18, 6}, {24, 7}, {38,8}}, // volume == 4
                     {{16, 9}, {42, 10}}, // volume == 8
                     {{0, 11}} // volume = 64
                    };
    GetIpClassTest();

    binarySearchThreshold = 2; // force binary search
    GetIpClassTest();
    binarySearchThreshold = defaultBinarySearchThreshold;

    // This test depends on particular database data (VAGGR_NETWORK_CLASSES).
    // Modify it if necessary.
    std::string errDescr;
    RefreshClassesFromDB();
    assert(GetIpClass(0) == 408);
    assert(GetIpClass(86884352) == 302); // first IP of network of size 16384
    assert(GetIpClass(86900735) == 302); // last IP of this network
    assert(GetIpClass(86900736) == 408); // next IP after last, it does not belong to that network!
    assert(GetIpClass(170000000) == 304); // IP from large network of size 16777216
    assert(GetIpClass(1317701384) == 303); // some particular IPs
    assert(GetIpClass(1317701386) == 302);
    assert(GetIpClass(1400000000) == 408);
    assert(GetIpClass(1410490368) == 273); // first IP from network of size 8192
    assert(GetIpClass(1410491500) == 273); // intermediate IP from the same network
    assert(GetIpClass(1410497738) == 302); // particular IP of another class inside bigger network
    assert(GetIpClass(1410498560) == 408); // next IP after last (corner case)
    assert(GetIpClass(2999914498) == 303); // IP from small inside bigger network
    assert(GetIpClass(2999914510) == 303); // similar case
    assert(GetIpClass(2999914532) == 1453211);
    assert(GetIpClass(2999915071) == 8799710);
    assert(GetIpClass(3648438086) == 303);
    assert(GetIpClass(4294967295) == 408); // last IP from 32-bit range
}

void NetworkClassificator::GetIpClassTest()
{
    assert(GetIpClass(0) == 11);
    assert(GetIpClass(20) == 1);
    assert(GetIpClass(18) == 6);
    assert(GetIpClass(21) == 6);
    assert(GetIpClass(23) == 9);
    assert(GetIpClass(24) == 7);
    assert(GetIpClass(27) == 7);
    assert(GetIpClass(28) == 11);
    assert(GetIpClass(50) == 4);
    assert(GetIpClass(100) == 0);
}
