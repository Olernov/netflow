#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <memory.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <iostream>
#include <queue>


std::vector<std::string> writePaths;
size_t writePathIndex = 0;
size_t maxFileSizeMb = 100;
size_t maxFileTimeSec = 60;
unsigned long udpPort = 7000;
bool stopFlag = false;

void printUsage(char* programName)
{
    std::cout << "Usage: " << std::endl << programName
              << " -w WRITE-PATH1 [-w WRITE_PATH2 ...]-p PORT] [-s MAXSIZE] [-t MAXTIME]" << std::endl
              << "    WRITE-PATHn\tpaths to store written files. At least one path must be given." << std::endl
              << "         If more than one path is given, then output files are written " << std::endl
              << "         sequentially from first path to the last." << std::endl
              << "    PORT\tUDP port to receive netflow datagrams. Default 7000" << std::endl
              << "    MAXSIZE\tmaximum size of written file (megabytes). Default 100" << std::endl
              << "    MAXTIME\tmaximum time of collecting data for one file (seconds). Default 60" << std::endl;
}


void SignalHandler(int signum, siginfo_t *info, void *ptr)
{
    std::cout << "Received signal #" <<signum << " from process #" << info->si_pid << ". Stopping ..." << std::endl;
    stopFlag = true;
}


FILE* OpenNewFile(time_t* fileStartTime, char* filename)
{
    time(fileStartTime);
    tm* tmp = localtime(fileStartTime);
    char strTime[200];
    strftime(strTime, sizeof(strTime), "%Y%m%d%H%M%S", tmp);
    sprintf(filename, "%s/nf%s", writePaths[writePathIndex++].c_str(), strTime);
    if (writePathIndex >= writePaths.size()) {
        writePathIndex = 0;
    }
    FILE* f = fopen(filename, "w");
    return f;
}


void WritePacketsToFiles(int udpSocket)
{
    char recvBuf[65535];
    FILE* outFile = nullptr;
    size_t fileSize = 0;
    size_t maxFileSize = maxFileSizeMb * 1024 * 1024;
    time_t fileStartTime = 0;
    char partialFileName[1024];

    while(!stopFlag) {
        int recvBytes = recv(udpSocket, recvBuf, sizeof(recvBuf), 0);
        if (recvBytes == -1 && errno!= EAGAIN && errno!= EINTR) {
            std::cerr << "Error #" << errno << " while recv() call." << std::endl;
        }
        else if (recvBytes > 0) {
            if (outFile == nullptr || (fileSize + recvBytes) > maxFileSize
                    || difftime(time(nullptr), fileStartTime) > maxFileTimeSec) {
                if (outFile != nullptr) {
                    fclose(outFile);
                    char finalFileName[1024];
                    sprintf(finalFileName, "%s.dat", partialFileName);
                    rename(partialFileName, finalFileName);
                }
                outFile = OpenNewFile(&fileStartTime, partialFileName);
            }
            if (outFile == nullptr) {
                std::cerr << "Unable to open file " << partialFileName << " for writing." << std::endl;
                continue;
            }
            else {
                fileSize = 0;
            }
            size_t writtenBytes = fwrite(recvBuf, 1, recvBytes, outFile);
            if (writtenBytes < recvBytes) {
                std::cerr << "Unable to write " << recvBytes << " bytes to " << partialFileName
                          << ". Only " << writtenBytes << " bytes written." << std::endl;
            }
            fileSize += writtenBytes;
        }
    }
}


int main(int argc, char *argv[])
{
    if (argc < 2) {
        printUsage(argv[0]);
        exit(EXIT_FAILURE);
    }


    int opt;
    while((opt = getopt(argc, argv, "w:p:s:t:")) != -1) {
        switch(opt) {
            case 'w':
                writePaths.push_back(optarg);
                break;
            case 'p':
                udpPort = atoi(optarg);
                break;
            case 's':
                maxFileSizeMb = atoi(optarg);
                break;
            case 't':
                maxFileTimeSec = atoi(optarg);
                break;
            default:
                printUsage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (writePaths.empty()) {
        std::cerr << "At least one write path must be specified." << std::endl;
        printUsage(argv[0]);
        exit(EXIT_FAILURE);
    }
    if (!(udpPort >= 1024 && udpPort <= 65535)) {
        std::cerr << "Valid values for PORT are from 1024 to 65535." << std::endl;
        printUsage(argv[0]);
        exit(EXIT_FAILURE);
    }
    if (!(maxFileSizeMb >= 1 && maxFileSizeMb <= 1024)) {
        std::cerr << "Valid values for MAXSIZE are from 1 to 1024." << std::endl;
        printUsage(argv[0]);
        exit(EXIT_FAILURE);
    }
    if (!(maxFileTimeSec >= 5 && maxFileTimeSec <= 600)) {
        std::cerr << "Valid values for MAXTIME are from 5 to 600." << std::endl;
        printUsage(argv[0]);
        exit(EXIT_FAILURE);
    }

    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = SignalHandler;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);

    int udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpSocket < 0) {
        std::cerr << "Unable to create server socket SOCK_DGRAM, IPPROTO_UDP.";
        exit(EXIT_FAILURE);
    }
    //int optval = 1;
    //setsockopt(udpSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    struct timeval tv;
    tv.tv_sec = 1;
    setsockopt(udpSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in serverAddr;
    memset((char *) &serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(udpPort);
    if (bind(udpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) != 0) {
        std::cerr << "Failed to call bind on server socket. Error #" + std::to_string(errno);
        exit(EXIT_FAILURE);
    }
    std::cout << "Netflow collector started at port " << udpPort << std::endl;

    WritePacketsToFiles(udpSocket);

    shutdown(udpSocket, SHUT_RDWR);
    close(udpSocket);
    std::cout << "Netflow collector finished." << std::endl;
    exit(EXIT_SUCCESS);
}

