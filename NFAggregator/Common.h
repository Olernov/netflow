#pragma once
#include <map>
#include <stdint.h>
#include <stdio.h>
#include <memory.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>





const unsigned long long emptyValueULL = -1;
const unsigned long emptyValueUL = -1;

const std::string crlf = "\r\n";

const int mainThreadIndex = -1;

const uint32_t megabyteSizeInBytes = 1024 * 1024;
const size_t maxAlertMessageLen = 2000;

const time_t notInitialized = 0;

enum ExportResult
{
	erSuccess = 0,
	erDBError
};

enum AggregationTestType
{
	noTest = 0,
	perFileTest = 1,
	totalTest = 2
};



