#include "FileWriter.h"

int CFileWriter::Init (size_t p_stBufSize)
{
	m_stBufSize = p_stBufSize;
    m_pmbBuf = new uint8_t[m_stBufSize];

	return 0;
}

int CFileWriter::CreateOutputFile(char *p_pszFileName,
    bool p_bRewrFile)
{
	// Если имя файла не задано, присваиваем значение по умолчанию
	if (NULL == p_pszFileName) {
		return -1;
	}
	if (INVALID_HANDLE_VALUE != m_hFile) {
		return -1;
	}

	DWORD dwLastError;
	char mcFileName[MAX_PATH];

	strcpy_s(
		mcFileName,
		sizeof(mcFileName)/sizeof(*mcFileName),
		p_pszFileName);

	char mcDrive[8];
	char mcDir[MAX_PATH];
	char mcFileTitle[MAX_PATH];
	char mcFileExt[MAX_PATH];

	_splitpath_s(
		p_pszFileName,
		mcDrive, sizeof(mcDrive)/sizeof(*mcDrive),
		mcDir, sizeof(mcDir)/sizeof(*mcDir),
		mcFileTitle, sizeof(mcFileTitle)/sizeof(*mcFileTitle),
		mcFileExt, sizeof(mcFileExt)/sizeof(*mcFileExt));

	DWORD dwNumber = 0;

	do {
		if (p_bRewrFile) {
			m_hFile = CreateFileA(
				mcFileName,
				GENERIC_WRITE,
				FILE_SHARE_READ,
				NULL,
				CREATE_ALWAYS,
				0,
				NULL);
		}
		else {
			m_hFile = CreateFileA(
				mcFileName,
				GENERIC_WRITE,
				FILE_SHARE_READ,
				NULL,
				CREATE_NEW,
				0,
				NULL);
		}
		if (INVALID_HANDLE_VALUE == m_hFile) {
			dwLastError = GetLastError();
			if (ERROR_FILE_EXISTS == dwLastError ) {
				sprintf_s(
					mcFileName,
					"%s%s%s#%03u%s",
					mcDrive,
					mcDir,
					mcFileTitle,
					dwNumber,
					mcFileExt);
			}
			else {
				break;
			}
		}
		else {
			break;
		}
	} while (256 > ++dwNumber);

	return 0;
}

int CFileWriter::WriteData(
	BYTE *p_bpData,
	size_t p_stDataSize)
{
	if (INVALID_HANDLE_VALUE == m_hFile) {
		return -1;
	}
	if (NULL == m_pmbBuf) {
		return -1;
	}

	size_t stBytesToCopy;
	size_t stDataReadInd;

	stDataReadInd = 0;
	stBytesToCopy = 0;

	while (stDataReadInd < p_stDataSize) {
		if (m_stCurPos == m_stBufSize) {
			if (! Finalise()) {
				return -1;
			}
		}
		stBytesToCopy = m_stBufSize - m_stCurPos > p_stDataSize - stDataReadInd ?
			p_stDataSize - stDataReadInd
			: m_stBufSize - m_stCurPos;
		if (stBytesToCopy) {
			memcpy(
				&(m_pmbBuf[m_stCurPos]),
				&(p_bpData[stDataReadInd]),
				stBytesToCopy);
			stDataReadInd += stBytesToCopy;
			m_stCurPos += stBytesToCopy;
		}
	}

	return 0;
}

int CFileWriter::Finalise()
{
	DWORD dwBytesWritten;

	if (INVALID_HANDLE_VALUE == m_hFile) {
		return -1;
	}
	if (m_stCurPos) {
		if (! WriteFile(
			m_hFile,
			m_pmbBuf,
			(DWORD)m_stCurPos,
			&dwBytesWritten,
			NULL)) {
				return -1;
		}
		if (dwBytesWritten != (size_t)dwBytesWritten) {
			return -1;
		}
		FlushFileBuffers (m_hFile);
		m_stCurPos = 0;
	}

	return 0;
}

CFileWriter::CFileWriter(void)
{
	m_pmbBuf = NULL;
	m_stBufSize = 0;
	m_stCurPos = 0;
	m_hFile = INVALID_HANDLE_VALUE;
}

CFileWriter::~CFileWriter(void)
{
	if (m_pmbBuf) {
		delete[] m_pmbBuf;
		m_pmbBuf = NULL;
	}
	m_stBufSize = 0;
	m_stCurPos = 0;
	if (INVALID_HANDLE_VALUE != m_hFile) {
		CloseHandle (m_hFile);
		m_hFile = INVALID_HANDLE_VALUE;
	}
}
