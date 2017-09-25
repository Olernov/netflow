#pragma once
#include <vector>
#include <boost/thread/shared_mutex.hpp>
#include "DBConnect.h"


class NetworkClassificator
{
public:
    NetworkClassificator(DBConnect& db);
    void RefreshClassesFromDB();
    uint32_t GetIpClass(uint32_t ipAddress);
    void RunTests();
private:
    typedef std::vector<std::pair<uint32_t, uint32_t>> NetClassVector; // pairs of IP - netClassId
    static const size_t defaultBinarySearchThreshold = 1000;
    size_t binarySearchThreshold;
    DBConnect& dbConnect;
    std::vector<uint64_t> networkVolumes;
    std::vector<NetClassVector> netClassTable;
    boost::shared_mutex mutex;

    uint32_t BinarySearchForNetwork(uint32_t ipAddress, size_t rowIndex, size_t from, size_t to);
    uint32_t FullScanForNetwork(uint32_t ipAddress, size_t rowIndex);

    void GetIpClassTest();
};
