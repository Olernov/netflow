#include <boost/filesystem.hpp>
#include "MainLoopController.h"
#include "LogWriterOtl.h"
#include "Config.h"
#include "FileReader.h"
#include "NFParser.h"
#include "AlertSender.h"

extern LogWriterOtl logWriter;
extern AlertSender alertSender;

MainLoopController::MainLoopController(const Config& config, size_t pind) :
    config(config),
    processIndex(pind),
    lastAlertTime(notInitialized),
    shutdownFlag(false),
    billingInfo(config.connectString),
    aggregator(config, &billingInfo)
{
}


void MainLoopController::Run()
{
    aggregator.Initialize();
    nfParser.Initialize(&aggregator);
    filesystem::path cdrPath(config.inputDirs[processIndex]);
    bool allCdrProcessed = false;
    std::string lastPostponeReason;
    time_t lastCdrFileTime = time(nullptr);
    while(!shutdownFlag) {
        std::string postponeReason;
        if (!aggregator.CanContinueProcessing(postponeReason)) {
            if (postponeReason != lastPostponeReason) {
                logWriter << "Processing new files postponed due to: " + postponeReason;
                lastPostponeReason = postponeReason;
            }
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }
        else {
             lastPostponeReason.clear();
        }

        fileList sourceFiles;
        ConstructSortedFileList(config.inputDirs[processIndex], config.cdrExtension, sourceFiles);
        if (sourceFiles.size() > 0) {
            allCdrProcessed = false;
            for (auto& file : sourceFiles) {
                if (!aggregator.CanContinueProcessing(postponeReason)) {
                    break;
                }

                lastCdrFileTime = time(nullptr);
                logWriter << "Processing file " + file.filename().string() + "...";
                time_t processStartTime;
                time(&processStartTime);
                CFileReader fileReader;
                int frInitRes = fileReader.Init(fileReaderChunkSize);
                if (frInitRes != 0) {
                    logWriter << "Failed to init FileReader. Error code: "
                                 + std::to_string(frInitRes);
                    continue;
                }
                int frOpenRes = fileReader.OpenDataFile(file.string());
                if (frOpenRes != 0) {
                    logWriter << "Failed to OpenDataFile with FileReader. Error code: "
                                 + std::to_string(frOpenRes);
                    continue;
                }
                nfParser.ResetCounters();
                std::string errorDescr;
                while(nfParser.ProcessNextExportPacket(fileReader, errorDescr)) {
                    ;
                }
                if (!errorDescr.empty()) {
                    logWriter << errorDescr;
                }

                fileReader.CloseDataFile();
                long processTimeSec = difftime(time(nullptr), processStartTime);
                logWriter << "File " + file.filename().string() + " processed in " +
                             std::to_string(processTimeSec) + " sec. Data records: " +
                             std::to_string(nfParser.GetDataRecordsCount()) + ". Templates: " +
                             std::to_string(nfParser.GetTemplatesCount());

                filesystem::path archivePath(config.archiveDirs[processIndex]);
                filesystem::path archiveFilename = archivePath / file.filename();
                filesystem::rename(file, archiveFilename);

                if (shutdownFlag) {
                    break;
                }
            }
        }
        if (sourceFiles.empty()) {
            if (!allCdrProcessed) {
                allCdrProcessed = true;
                logWriter << "All CDR files processed.";
            }
            double diff = difftime(time(nullptr), lastCdrFileTime) / 60;
            if (diff >= config.noCdrAlertPeriodMin) {
                tm* tmp = localtime(&lastCdrFileTime);
                char strTime[200];
                strftime(strTime, sizeof(strTime), "%d.%m.%Y %T", tmp);
                alertSender.SendAlert("Incoming files are missing in "
                                      + config.inputDirs[processIndex] + " since "
                                      + std::string(strTime));
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    logWriter << "Shutting down ...";
    aggregator.Stop();
}


void MainLoopController::ConstructSortedFileList(const std::string& inputDir,
                                                 const std::string& cdrExtension,
                                                 fileList& sourceFiles)
{
    filesystem::path inputPath(inputDir);
    filesystem::directory_iterator endIterator;
    for(filesystem::directory_iterator iter(inputPath); iter != endIterator; iter++) {
        if (filesystem::is_regular_file(iter->status())
                && iter->path().extension() == config.cdrExtension) {
            sourceFiles.push_back(iter->path());
        }
    }
    std::sort(sourceFiles.begin(), sourceFiles.end());
}


void MainLoopController::Stop()
{
    shutdownFlag = true;
}

