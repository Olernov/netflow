#include <boost/filesystem.hpp>
#include "MainLoopController.h"
#include "LogWriterOtl.h"
#include "Config.h"
#include "FileReader.h"
#include "NFParser.h"
#include "AlertSender.h"

extern LogWriterOtl logWriter;
extern AlertSender alertSender;

MainLoopController::MainLoopController(const Config& config) :
    config(config),
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

    filesystem::path cdrPath(config.inputDir);
    bool allCdrProcessed = false;
    std::string lastPostponeReason;
    time_t lastCdrFileTime = time(nullptr);
    while(!shutdownFlag) {

        fileList sourceFiles;
        ConstructSortedFileList(config.inputDir, config.cdrExtension, sourceFiles);
        if (sourceFiles.size() > 0) {
            allCdrProcessed = false;
            for (auto& file : sourceFiles) {
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

                while(nfParser.ProcessNextExportPacket(fileReader)) {
                    ;
                }

                fileReader.CloseDataFile();
                double processTimeSec = difftime(time(nullptr), processStartTime);
                logWriter << "File " + file.filename().string() + " processed in " +
                             std::to_string(processTimeSec) + " sec.";

                filesystem::path archivePath(config.archiveDir);
                filesystem::path archiveFilename = archivePath / file.filename();
                filesystem::rename(file, archiveFilename);

//                    if (parser.IsReady()) {
//                        lastPostponeReason.clear();
//                        parser.ProcessFile(file);
//                    }
//                    else {
//                        if (lastPostponeReason != parser.GetPostponeReason()) {
//                            lastPostponeReason = parser.GetPostponeReason();
//                            logWriter.Write("CDR processing postponed due to: " + lastPostponeReason, mainThreadIndex);
//                        }
//                        Sleep();
//                    }
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
                alertSender.SendAlert("Incoming files are missing since " + std::string(strTime));
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
                && iter->path().extension() == cdrExtension) {
            sourceFiles.push_back(iter->path());
        }
    }
    std::sort(sourceFiles.begin(), sourceFiles.end());
}


void MainLoopController::Stop()
{
    shutdownFlag = true;
}

