#include <iostream>
#include <cassert>
#include <signal.h>
#include "OTL_Header.h"
#include "DBConnect.h"
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


void printUsage()
{
    std::cerr << "IRBiS netflow aggregator. (c) Tenet Ltd. 2017" << std::endl
            << "Usage: " << std::endl << "nf-aggregator <config-file> [-test|-detail]" << std::endl
            << "     -test runs unit tests and exits" << std::endl
            << "     -detail runs detailed export of netflow data with no aggregation" << std::endl;
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
    if (argc > 2 && !strncasecmp(argv[2], "-detail", 7)) {
        config.detailedExport = true;
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

        logWriter << "Netflow aggregator started";
        logWriter << config.DumpAllSettings();
        std::cout << "Netflow aggregator started" << std::endl;
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
