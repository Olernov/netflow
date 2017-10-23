#include <iostream>
#include <cassert>
#include <signal.h>
#include "OTL_Header.h"
#include "DBConnect.h"
//#include "Utils.h"
#include "otl_utils.h"
#include "Session.h"
#include "Common.h"
#include "MainLoopController.h"
#include "LogWriterOtl.h"
#include "Config.h"
#include "AlertSender.h"

Config config;
LogWriterOtl logWriter;
AlertSender alertSender("Netflow aggregator");
MainLoopController* mainLoopCtrl = nullptr;

void log(short msgType, std::string msgText)
{
    std::cout << msgText << std::endl;
}


void ClearTestExportTable(DBConnect& dbConnect)
{
    otl_stream dbStream;
    dbStream.open(1, "call Billing.Netlow.ClearTAggregate()", dbConnect);
    dbStream.close();
}


void CheckExportedData(DBConnect& dbConnect)
{
    otl_stream otlStream;
    otlStream.open(1, "call Billing.Netlow.CheckTestExport()", dbConnect);
    otlStream.close();
}


void RunStoredLogicTests(DBConnect& dbConnect)
{
    std::cout << "Running stored database logic tests ..." << std::endl;
    otl_stream otlStream;
    otlStream.open(1, "call Billing.Netlow.RunAllTests()", dbConnect);
    otlStream.close();
}


void printUsage()
{
    std::cerr << "Usage: " << std::endl << "nf-aggregator <config-file> [-test]" << std::endl;
}


void SignalHandler(int signum, siginfo_t *info, void *ptr)
{
    std::cout << "Received signal #" <<signum << " from process #" << info->si_pid << ". Stopping ..." << std::endl;
    mainLoopCtrl->Stop();
}


int main(int argc, const char* argv[])
{
    if (argc < 2) {
        printUsage();
        exit(EXIT_FAILURE);
    }
    const char* confFilename = argv[1];
    bool runTests = false;
    if (argc > 2 && !strncasecmp(argv[2], "-test", 5)) {
        runTests = true;
    }
    std::ifstream confFile(confFilename, std::ifstream::in);
    if (!confFile.is_open()) {
        std::cerr << "Unable to open config file " << confFilename << std::endl;
        exit(EXIT_FAILURE);
    }
    try {
        config.ReadConfigFile(confFile);
        config.ValidateParams();
    }
    catch(const std::exception& ex) {
        std::cerr << "Error when parsing config file " << confFilename << std::endl;
        std::cerr << ex.what() <<std::endl;
        exit(EXIT_FAILURE);
    }

    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = SignalHandler;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);

    size_t processIndex = 0;
    // fork new process for every input directory
    while (++processIndex <= config.inputDirs.size()) {
        if (processIndex == config.inputDirs.size()) {
            // stop forking
            processIndex = 0;
            break;
        }
        pid_t pid = fork();
        if (pid < 0) {
            std::cerr << "Unable to fork. Error code " << errno << std::endl;
            exit(EXIT_FAILURE);
        }
        if (pid > 0) {
            // we are in child process
            break;
        }
    }

    const std::string pidFilename = "/var/run/nf-aggregator" + std::to_string(processIndex) + ".pid";
    std::ofstream pidFile(pidFilename, std::ofstream::out);
    if (pidFile.is_open()) {
        pidFile << getpid();
    }
    pidFile.close();

    logWriter.Initialize(config.logDirs[processIndex], "nf", config.logLevel);

    const int OTL_MULTITHREADED_MODE = 1;
    otl_connect::otl_initialize(OTL_MULTITHREADED_MODE);

    try {
        alertSender.Initialize(config.connectString);
        if (runTests) {
            std::cout << "Running tests ..." << std::endl;
            BillingInfo testBI(config.connectString);
            testBI.RunTests();
            std::cout << "Tests PASSED" << std::endl;
            exit(EXIT_SUCCESS);
        }

        logWriter << "Netflow aggregator start";
        logWriter << config.DumpAllSettings();
        mainLoopCtrl = new MainLoopController(config, processIndex);
        mainLoopCtrl->Run();
    }
    catch(otl_exception& ex) {
        std::string errMessage = OTL_Utils::OtlExceptionToText(ex);
        std::cerr << errMessage << std::endl;
        logWriter.Write(errMessage, mainThreadIndex, error);
    }
    catch(std::exception& ex) {
        std::cerr << ex.what() << std::endl;
        logWriter.Write(ex.what(), mainThreadIndex, error);
    }
    delete mainLoopCtrl;
    logWriter << "Netflow aggregator shutdown";
    remove(pidFilename.c_str());
    return 0;
}
