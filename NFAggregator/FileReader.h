#pragma once
#include "Common.h"

const int MAX_PATH = 4096;

struct SFileInfo {
    char m_mcDir[MAX_PATH];
    char m_mcFileName[MAX_PATH];
};

class CFileReader
{
public:
	int Init (size_t stReadChunkSize);
    int OpenDataFile (const std::__cxx11::string &filename);
	size_t ReadData(
        uint8_t **p_ppmbData,
        size_t uint8_tsToRead);
	int CloseDataFile();
	const char * GetDir() { return m_soFileInfo.m_mcDir; }
	const char * GetFileName() { return m_soFileInfo.m_mcFileName; }
public:
	CFileReader(void);
	~CFileReader(void);
private:
    int ReadDataFromFile (size_t stRequestedDataSize);
private:
    uint8_t *m_pmbData;
	size_t m_stBufferSize;
	size_t m_stReadChunkSize;
	size_t m_stBufferedDataSize;
	size_t m_stCurPos;
    FILE* m_hFile;
    SFileInfo m_soFileInfo;
};
