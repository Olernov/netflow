#pragma once


class CFileReader
{
public:
	int Init (size_t stReadChunkSize);
	int OpenDataFile (SFileInfo * p_psoFileInfo);
	size_t ReadData(
		BYTE __out **p_ppmbData,
		size_t __in bytesToRead);
	int CloseDataFile();
	const char * GetDir() { return m_soFileInfo.m_mcDir; }
	const char * GetFileName() { return m_soFileInfo.m_mcFileName; }
public:
	CFileReader(void);
	~CFileReader(void);
private:
	BOOL ReadDataFromFile (size_t stRequestedDataSize);
private:
	BYTE *m_pmbData;
	size_t m_stBufferSize;
	size_t m_stReadChunkSize;
	size_t m_stBufferedDataSize;
	size_t m_stCurPos;
	HANDLE m_hFile;
	HANDLE m_hMemHeap;
	SFileInfo m_soFileInfo;
};
