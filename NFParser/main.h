#pragma once

class CFileWriter;

/*	Параметр командной строки
 */
struct SCmdLineParam {
	char m_pszParamId[16];
	char m_pszParamName[32];
	BYTE m_mbValue[256];
};

struct SFileInfo {
	char m_mcDir[MAX_PATH];
	char m_mcFileName[MAX_PATH];
};

int ParseCmdLine(
	int p_iArgC,
	char *p_mpszArgV[],
	std::multimap<std::string,std::string> *p_pmmapParamList,
	SCmdLineParam *p_pmsoParamDef,
	size_t p_stParamCnt);

void ExtractFileTimeStamp(
	const char *p_pcszFileName,
	char *p_pszOut,
	size_t p_stOutSize);

void CreateFileList(
	const char *p_pcszDir,
	std::multimap<std::string,SFileInfo> *p_pmmapFileList);
