#include "FileReader.h"

int CFileReader::Init (size_t stReadChunkSize)
{
	m_stReadChunkSize = stReadChunkSize;
	m_stBufferSize = m_stReadChunkSize * 2;
	m_hMemHeap = HeapCreate(
		0,
		m_stBufferSize,
		0);
	if (NULL == m_hMemHeap) {
		return -1;
	}
	m_pmbData = (BYTE*)HeapAlloc(
		m_hMemHeap,
		HEAP_NO_SERIALIZE,
		m_stBufferSize);
	if (NULL == m_pmbData) {
		return -1;
	}

	return 0;
}

int CFileReader::OpenDataFile (SFileInfo * p_psoFileInfo)
{
	if (INVALID_HANDLE_VALUE != m_hFile) {
		return -1;
	}
	strcpy_s(
		m_soFileInfo.m_mcDir,
		sizeof(m_soFileInfo.m_mcDir)/sizeof(*m_soFileInfo.m_mcDir),
		p_psoFileInfo->m_mcDir);
	strcpy_s(
		m_soFileInfo.m_mcFileName,
		sizeof(m_soFileInfo.m_mcFileName)/sizeof(*m_soFileInfo.m_mcFileName),
		p_psoFileInfo->m_mcFileName);

	std::string strFileName;

	strFileName = p_psoFileInfo->m_mcDir;
	strFileName += "\\";
	strFileName += p_psoFileInfo->m_mcFileName;

	m_hFile = CreateFileA(
		strFileName.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	if (INVALID_HANDLE_VALUE == m_hFile) {
		return GetLastError();
	}
	else {
		m_stBufferedDataSize = 0;
		m_stCurPos = 0;
		return 0;
	}
}

size_t CFileReader::ReadData(
	BYTE __out **p_ppmbData,
	size_t __in bytesToRead)
{
	if (INVALID_HANDLE_VALUE == m_hFile) {
		return 0;
	}
	if (0 == bytesToRead) {
		return 0;
	}

	if (m_stBufferedDataSize - m_stCurPos < bytesToRead) {
		if (0 != ReadDataFromFile (bytesToRead)) {
			*p_ppmbData = NULL;
			return 0;
		}
	}

	*p_ppmbData = &(m_pmbData[m_stCurPos]);
	m_stCurPos += bytesToRead;

	return bytesToRead;
}

int CFileReader::CloseDataFile()
{
	if (INVALID_HANDLE_VALUE != m_hFile) {
		CloseHandle (m_hFile);
		m_hFile = INVALID_HANDLE_VALUE;
		return 0;
	}
	else {
		return -1;
	}
}

CFileReader::CFileReader(void)
{
	m_pmbData = NULL;
	m_stBufferSize = 0;
	m_stReadChunkSize = 0;
	m_stBufferedDataSize = 0;
	m_stCurPos = 0;
	m_hFile = INVALID_HANDLE_VALUE;
	m_hMemHeap = NULL;
}

CFileReader::~CFileReader(void)
{
	if (NULL != m_hMemHeap) {
		HeapDestroy (m_hMemHeap);
		m_hMemHeap = NULL;
	}
	if (INVALID_HANDLE_VALUE != m_hFile) {
		CloseHandle (m_hFile);
		m_hFile = INVALID_HANDLE_VALUE;
	}
}

int CFileReader::ReadDataFromFile (size_t stRequestedDataSize)
{
	DWORD dwBytesRead;

	if (m_stCurPos + stRequestedDataSize > m_stBufferSize) {
		// возможно здесь стоило бы попытаться увеличить буфер
		//return ERROR_INSUFFICIENT_BUFFER;
	}
	if ( m_stBufferedDataSize == 0 || m_stCurPos > m_stReadChunkSize) {
		if (!ReadFile(
			m_hFile,
			m_pmbData,
			m_stReadChunkSize,
			&dwBytesRead,
			NULL)) {
				return GetLastError();
		}
		if (dwBytesRead < stRequestedDataSize) {
			return -1;
		}
		m_stCurPos = 0;
		m_stBufferedDataSize = dwBytesRead;
	}
	else {
		size_t stBytesToRead = stRequestedDataSize - m_stBufferedDataSize + m_stCurPos;
		if (!ReadFile(
			m_hFile,
			&(m_pmbData[m_stBufferedDataSize]),
			stBytesToRead,
			&dwBytesRead,
			NULL)) {
				return GetLastError();
		}
		if (stBytesToRead != dwBytesRead) {
			return -1;
		}
		m_stBufferedDataSize += dwBytesRead;
	}
	
	return 0;
}
