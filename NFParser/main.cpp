// TestNetFlowV9.cpp : Defines the entry point for the console application.
//
#include "common.h"
#include <dirent.h>
#include "FileWriter.h"
#include "FileReader.h"
#include "Filter.h"
#include "StatKeeper.h"
#include "NFParser.h"

int main ( int argc, char* argv[] )
{
    int iRetVal = 0;

    SCmdLineParam msoParamDef[] = {
/*  0 */	{"srcip","Source ip-address",{0}},
/*  1 */	{"dstip","Destination ip-address",{0}},
/*  2 */	{"stime","Start time",{0}},
/*  3 */	{"etime","End time",{0}},
/*  4 */	{"rbuf","Read buffer size",{0}},
/*  5 */	{"wbuf","Write buffer size",{0}},
/*  6 */	{"ddir","Data files directory",{0}},
/*  7 */	{"rfile","Results file",{0}},
/*  8 */	{"rem","Remark",{0}},
/*  9 */	{"opdtflnm","Output data file name",{0}},
/* 10 */	{"shskflnm","Show skipped data file name",{0}},
/* 11 */	{ "ophdr", "Output packet header", { 0 } },
/* 12 */	{"optmplt","Output template",{0}},
/* 13 */	{"srcport","Source port",{0}},
/* 14 */	{"dstport","Destination port",{0}},
/* 15 */	{"/?","Help",{0}},
/* 16 */	{"useopf","Use output format",{0}},
/* 17 */	{"opfrw","Rewrite output file",{0}},
/* 18 */	{"cntpckt","Count packet number",{0}},
/* 19 */	{"dod","Do not output data",{0}}
    };

    int iFnRes = 0;
    std::multimap<std::string,std::string> mmapParamList;

    iFnRes = ParseCmdLine(
        argc,
        argv,
        &mmapParamList,
        msoParamDef,
        sizeof(msoParamDef)/sizeof(*msoParamDef));
    if (0 != iFnRes) {
            printf ("Error: command line parsing failed\n");
            iRetVal = -1;
            return iRetVal;
    }

    uint32_t dwParam;
    std::multimap<std::string,std::string>::iterator iterParam;

    iterParam = mmapParamList.find (msoParamDef[15].m_pszParamId);
    if (iterParam != mmapParamList.end()) {
        printf ("Command line parameters:\n");
        for (int i = 0; i < sizeof(msoParamDef)/sizeof(*msoParamDef); ++i) {
            printf(
                "%s\t%s\n",
                msoParamDef[i].m_pszParamId,
                msoParamDef[i].m_pszParamName);
        }
        printf ("\nPress any key to exit");
        char c;
        scanf("%c", c);
        return 0;
    }
    iterParam = mmapParamList.find (msoParamDef[5].m_pszParamId);
    CFileWriter coFileWriter;
    if (iterParam != mmapParamList.end()) {
        dwParam = atol ((const char*)iterParam->second.c_str());
    }
    else {
        dwParam = 0x1000000;
    }
    iFnRes = coFileWriter.Init (dwParam);
    if (0 != iFnRes) {
        printf("FileWriter.Init failed\n");
        return -1;
    }
    iterParam = mmapParamList.find (msoParamDef[7].m_pszParamId);
    if (iterParam != mmapParamList.end()) {
        std::string strFileName = iterParam->second.c_str();
        iterParam = mmapParamList.find (msoParamDef[17].m_pszParamId);
        if (iterParam != mmapParamList.end()) {
            iFnRes = coFileWriter.CreateOutputFile(
                (char*)(strFileName.c_str()),
                true);
        }
        else {
            iFnRes = coFileWriter.CreateOutputFile ((char*)(strFileName.c_str()));
        }
        if (0 != iFnRes) {
            printf(
                "Can't create file \"%s\"\n",
                strFileName.c_str());
            return false;
        }
    }
    else {
        iFnRes = coFileWriter.CreateOutputFile ("Output.txt");
        if (0 != iFnRes) {
            printf ("Can't create file \"Output.txt\"\n");
            return false;
        }
    }

    CFileReader coFileReader;
    iterParam = mmapParamList.find (msoParamDef[4].m_pszParamId);
    if (iterParam != mmapParamList.end()) {
        dwParam = atol ((const char*)iterParam->second.c_str());
    }
    else {
        dwParam = 0x1000000;
    }
    iFnRes = coFileReader.Init (dwParam);
    if (0 != iFnRes) {
        printf("FileReader.Init failed\n");
        return -1;
    }

    char *pszSubStr;

    CFilter coFilter;
    tm tmTime;

    iterParam = mmapParamList.find (msoParamDef[2].m_pszParamId);
    if (iterParam != mmapParamList.end()) {
        memset(
            &tmTime,
            0,
            sizeof(tmTime));
        iFnRes = sscanf(
            iterParam->second.c_str(),
            "%u.%u.%u %u:%u:%u",
            &(tmTime.tm_mday),
            &(tmTime.tm_mon),
            &(tmTime.tm_year),
            &(tmTime.tm_hour),
            &(tmTime.tm_min),
            &(tmTime.tm_sec));
        --tmTime.tm_mon;
        tmTime.tm_year -= 1900;
        if (6 != iFnRes) {
            printf(
                "Error: Invalid format: parameter: \"%s\"; value: \"%s\"",
                msoParamDef[2].m_pszParamName,
                iterParam->second.c_str());
            return -1;
        }
        dwParam = (uint32_t) mktime (&tmTime);
        if (-1 == dwParam) {
            printf(
                "Error: mktime can't convert value: parameter: \"%s\"; value: \"%s\"",
                msoParamDef[2].m_pszParamName,
                iterParam->second.c_str());
            return -1;
        }
        coFilter.SetParameter(
            IDS_FIRST_SWITCHED,
            &dwParam,
            sizeof(dwParam));
    }
    iterParam = mmapParamList.find (msoParamDef[3].m_pszParamId);
    if (iterParam != mmapParamList.end()) {
        memset(
            &tmTime,
            0,
            sizeof(tmTime));
        iFnRes = sscanf(
            iterParam->second.c_str(),
            "%u.%u.%u %u:%u:%u",
            &(tmTime.tm_mday),
            &(tmTime.tm_mon),
            &(tmTime.tm_year),
            &(tmTime.tm_hour),
            &(tmTime.tm_min),
            &(tmTime.tm_sec));
        --tmTime.tm_mon;
        tmTime.tm_year -= 1900;
        if (6 != iFnRes) {
            printf(
                "Error: Invalid format: parameter: \"%s\"; value: \"%s\"",
                msoParamDef[3].m_pszParamName,
                iterParam->second.c_str());
            return -1;
        }
        dwParam = (uint32_t) mktime (&tmTime);
        if (-1 == dwParam) {
            printf(
                "Error: mktime can't convert value: parameter: \"%s\"; value: \"%s\"",
                msoParamDef[3].m_pszParamName,
                iterParam->second.c_str());
            return -1;
        }
        coFilter.SetParameter(
            IDS_LAST_SWITCHED,
            &dwParam,
            sizeof(dwParam));
    }
    iterParam = mmapParamList.find (msoParamDef[0].m_pszParamId);
    if (iterParam != mmapParamList.end()) {
        pszSubStr = strstr(
            (char*)(iterParam->second.c_str()),
            "/");
        if (pszSubStr) {
            *pszSubStr = '\0';	// ???????? ?????? ????? ??? ??????? ?????????????? ip-??????
        }
        dwParam = inet_addr (iterParam->second.c_str());
        if (INADDR_NONE == dwParam) {
            printf(
                "Error: inet_addr can't convert value: parameter: \"%s\"; value: \"%s\"",
                msoParamDef[0].m_pszParamName,
                iterParam->second.c_str());
            return -1;
        }
        dwParam = ntohl (dwParam);
        coFilter.SetParameter(
            IDS_IPV4_SRC_ADDR,
            &dwParam,
            sizeof(dwParam));
        if (pszSubStr) {
            *pszSubStr = '/';	// ??????????????? ???????? ??????
            ++pszSubStr;
            dwParam = atol (pszSubStr);
            if (0 == dwParam) {
                printf(
                    "Error: atol can't convert value: parameter: \"%s\"; value: \"%s\"",
                    "net mask",
                    pszSubStr);
                return -1;
            }
            dwParam = (uint32_t)(-1) << (sizeof(dwParam)*8 - dwParam);
            coFilter.SetParameter(
                IDS_SRC_MASK,
                &dwParam,
                sizeof(dwParam));
        }
    }
    iterParam = mmapParamList.find (msoParamDef[1].m_pszParamId);
    if (iterParam != mmapParamList.end()) {
        pszSubStr = strstr(
            (char*)(iterParam->second.c_str()),
            "/");
        if (pszSubStr) {
            *pszSubStr = '\0';
        }
        dwParam = inet_addr ((char*)(iterParam->second.c_str()));
        if (INADDR_NONE == dwParam) {
            printf(
                "Error: inet_addr can't convert value: parameter: \"%s\"; value: \"%s\"",
                msoParamDef[1].m_pszParamName,
                iterParam->second.c_str());
            return -1;
        }
        dwParam = ntohl (dwParam);
        coFilter.SetParameter(
            IDS_IPV4_DST_ADDR,
            &dwParam,
            sizeof(dwParam));
        if (pszSubStr) {
            *pszSubStr = '/';
            ++pszSubStr;
            dwParam = atol (pszSubStr);
            if (0 == dwParam) {
                printf(
                    "Error: atol can't convert value: parameter: \"%s\"; value: \"%s\"",
                    "net mask",
                    pszSubStr);
                return -1;
            }
            dwParam = (uint32_t)(-1) << (sizeof(dwParam)*8 - dwParam);
            coFilter.SetParameter(
                IDS_DST_MASK,
                &dwParam,
                sizeof(dwParam));
        }
    }
    uint16_t wPort;
    iterParam = mmapParamList.find (msoParamDef[13].m_pszParamId);
    if (iterParam != mmapParamList.end()) {
        wPort = (uint16_t) atol ((const char*)(iterParam->second.c_str()));
        coFilter.SetParameter(
            IDS_L4_SRC_PORT,
            &wPort,
            sizeof(wPort));
    }
    iterParam = mmapParamList.find (msoParamDef[14].m_pszParamId);
    if (iterParam != mmapParamList.end()) {
        wPort = (uint16_t) atol ((const char*)(iterParam->second.c_str()));
        coFilter.SetParameter(
            IDS_L4_DST_PORT,
            &wPort,
            sizeof(wPort));
    }

    bool bOutputFileName = false;
    iterParam = mmapParamList.find (msoParamDef[9].m_pszParamId);
    if (iterParam != mmapParamList.end()) {
        bOutputFileName = true;
    }
    bool bShowSkipped = false;
    iterParam = mmapParamList.find (msoParamDef[10].m_pszParamId);
    if (iterParam != mmapParamList.end()) {
        bShowSkipped = true;
    }
    uint32_t dwParserFlags = 0;
    iterParam = mmapParamList.find (msoParamDef[11].m_pszParamId);
    if (iterParam != mmapParamList.end()) {
        dwParserFlags |= OUTPUT_NFPCKTHEADER;
    }
    iterParam = mmapParamList.find (msoParamDef[12].m_pszParamId);
    if (iterParam != mmapParamList.end()) {
        dwParserFlags |= OUTPUT_NFTEMPLATE;
    }
    iterParam = mmapParamList.find (msoParamDef[16].m_pszParamId);
    if (iterParam != mmapParamList.end()) {
        dwParserFlags |= OUTPUT_USEOPT;
    }
    iterParam = mmapParamList.find (msoParamDef[18].m_pszParamId);
    if (iterParam != mmapParamList.end()) {
        dwParserFlags |= OUTPUT_CNTPCKTS;
    }
    iterParam = mmapParamList.find (msoParamDef[19].m_pszParamId);
    if (iterParam != mmapParamList.end()) {
        dwParserFlags |= OUTPUT_DOD;
    }

    iterParam = mmapParamList.begin();
    while (iterParam != mmapParamList.end()) {
        size_t stStrLen;
        stStrLen = iterParam->first.length();
        if (0 != coFileWriter.WriteData(
            (uint8_t*)(iterParam->first.c_str()),
            stStrLen)) {
                printf ("CFileWriter.WriteData failed\n");
                return -1;
        }
        if (iterParam->second.length()) {
            if (0 != coFileWriter.WriteData(
                (uint8_t*)": ",
                2)) {
                    printf ("CFileWriter.WriteData failed\n");
                    return -1;
            }
            if (0 != coFileWriter.WriteData(
                (uint8_t*)(iterParam->second.c_str()),
                iterParam->second.length())) {
                    printf ("CFileWriter.WriteData failed\n");
                    return -1;
            }
        }
        if (0 != coFileWriter.WriteData(
            (uint8_t*)"\r\n",
            2)) {
                printf ("CFileWriter.WriteData failed\n");
                return -1;
        }
        ++iterParam;
    }
    if (0 != coFileWriter.WriteData(
        (uint8_t*)"\r\n",
        2)) {
            printf ("CFileWriter.WriteData failed\n");
            return -1;
    }
    if (0 != coFileWriter.Finalise()) {
        printf ("CFileWriter.Finalise failed\n");
        return -1;
    }

    CStatKeeper coStatKeeper;
    CNFParser coParser (dwParserFlags & OUTPUT_CNTPCKTS);

    if (! coParser.Init(
        &coFileWriter,
        &coFileReader,
        &coFilter,
        &coStatKeeper,
        dwParserFlags)) {
            printf ("coParser.Init failed!\n");
            coFileWriter.WriteData(
                (uint8_t*)"coParser.Init failed!\r\n",
                23);
            return -1;
    }

    std::multimap<std::string,SFileInfo> mmapFileList;
    std::multimap<std::string,SFileInfo>::iterator iterFileList;
    std::string strFileName;


    auto dataDirs = mmapParamList.equal_range(msoParamDef[6].m_pszParamId);
    for (auto it = dataDirs.first; it != dataDirs.second; ++it) {
        CreateFileList(
            it->second.c_str(),
            &mmapFileList);
    }

    iterFileList = mmapFileList.begin();

    while (iterFileList != mmapFileList.end()) {
        do {
            char mcTime[128];

            strFileName = iterFileList->second.m_mcDir;
            strFileName += "/";
            strFileName += iterFileList->second.m_mcFileName;
            if (bOutputFileName) {
                coFileWriter.WriteData(
                    (uint8_t*)(strFileName.c_str()),
                    strFileName.length());
                coFileWriter.WriteData(
                    (uint8_t*)"\r\n",
                    2);
            }
            ExtractFileTimeStamp(
                iterFileList->first.c_str(),
                mcTime,
                sizeof(mcTime));
            if (! coFilter.FileFilter (iterFileList->first.c_str())) {
                coStatKeeper.CountFile(
                    iterFileList->first.c_str(),
                    true);
                if (bShowSkipped) {
                    printf(
                        "Data file: %s (%s) - skipped\n",
                        iterFileList->first.c_str(),
                        mcTime);
                }
                break;
            }
            printf(
                "Data file: %s (%s)",
                iterFileList->first.c_str(),
                mcTime);
            if (0 != coFileReader.OpenDataFile (&(iterFileList->second))) {
                coStatKeeper.CountFile(
                    iterFileList->first.c_str(),
                    true);
                break;
            }
            coStatKeeper.CountFile(
                iterFileList->first.c_str(),
                false);
            while (coParser.ReadNFPacket());
            printf(
                " - completed\n",
                iterFileList->first.c_str());
            coFileReader.CloseDataFile();
            coFileWriter.Finalise();
        } while (0);
        ++iterFileList;
    }

    coStatKeeper.OutputStat (&coFileWriter);
    coFileWriter.Finalise();

    return iRetVal;
}

int ParseCmdLine(
    int p_iArgC,
    char *p_mpszArgV[],
    std::multimap<std::string,std::string> *p_pmmapParamList,
    SCmdLineParam *p_pmsoCmdLineParam,
    size_t p_stParamCnt)
{
    int iRetVal = 0;
    int iParamInd;
    size_t
        stAttrNameLen,
        stParamLen;

    iParamInd = -1;
    for (int iArgInd = 0; iArgInd < p_iArgC; ++iArgInd) {
        stParamLen = strlen (p_mpszArgV[iArgInd]);
        for (size_t i=0; i < p_stParamCnt; ++i) {
            stAttrNameLen = strlen (p_pmsoCmdLineParam[i].m_pszParamId);
            if (stAttrNameLen > stParamLen) {
                continue;
            }
            if (0 == memcmp(
                p_mpszArgV[iArgInd],
                p_pmsoCmdLineParam[i].m_pszParamId,
                stAttrNameLen)) {
                    iParamInd = i;
                    break;
            }
        }
        if (-1 == iParamInd) {
            if (0 == iArgInd) {
                continue;
            }
            else {
                iRetVal = -1;
                printf(
                    "ParseCmdLine: Error: unknown parameter: %s\n",
                    p_mpszArgV[iArgInd]);
                break;
            }
        }
        std::string strParamVal;
        if (stParamLen > stAttrNameLen + 1) {
            stParamLen = stParamLen - stAttrNameLen - 1;
            strParamVal = &((p_mpszArgV[iArgInd])[stAttrNameLen+1]);
        }
        p_pmmapParamList->insert(
            std::make_pair(
                p_pmsoCmdLineParam[iParamInd].m_pszParamId,
                strParamVal));
    }

    return iRetVal;
}

void ExtractFileTimeStamp(
    const char *p_pcszFileName,
    char *p_pszOut,
    size_t p_stOutSize)
{
    int iFnRes;
    uint32_t dwRouterIp;
    uint64_t ullFileTime;
    uint32_t dwFileTime;
    tm soTm;

    iFnRes = sscanf(p_pcszFileName, "%x_%I64u", &dwRouterIp, &ullFileTime);
    if (2 != iFnRes) {
        *p_pszOut = '\0';
        return;
    }
    if ((uint64_t)20110400000000 <= ullFileTime) {
        soTm.tm_sec = ullFileTime%100;
        ullFileTime /= 100;
        soTm.tm_min = ullFileTime%100;
        ullFileTime /= 100;
        soTm.tm_hour = ullFileTime%100;
        ullFileTime /= 100;
        soTm.tm_mday = ullFileTime%100;
        ullFileTime /= 100;
        soTm.tm_mon = ullFileTime%100;
        --soTm.tm_mon;
        ullFileTime /= 100;
        soTm.tm_year = (int)ullFileTime;
        soTm.tm_year -= 1900;
        dwFileTime = (uint32_t) mktime (&soTm);
    }
    else {
        dwFileTime = (uint32_t)ullFileTime;
    }

    time_t ttTime;

    ttTime = (time_t) dwFileTime;
    gmtime_r (&ttTime, &soTm);
    strftime(
        p_pszOut,
        p_stOutSize,
        "%d.%m.%Y %H:%M:%S",
        &soTm);
}

void CreateFileList(
    const char *p_pcszDir,
    std::multimap<std::string,SFileInfo> *p_pmmapFileList)
{
    struct dirent **nameList;
    int entriesCnt = scandir(p_pcszDir, &nameList, nullptr, alphasort);
    if (entriesCnt  < 0) {
        return;
    }
    for (int i = 0; i < entriesCnt; ++i) {
        if (nameList[i]->d_name[0] != '.') {
            SFileInfo soFileInfo;
            strncpy(soFileInfo.m_mcDir, p_pcszDir, sizeof(soFileInfo.m_mcDir));
            strncpy(soFileInfo.m_mcFileName, nameList[i]->d_name, sizeof(soFileInfo.m_mcFileName));
            p_pmmapFileList->insert(std::make_pair(nameList[i]->d_name, soFileInfo));
        }
    }
    free(nameList);
}
