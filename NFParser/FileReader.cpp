#include "FileReader.h"

CFileReader::CFileReader(void)
{
    m_pmbData = nullptr;
    m_stBufferSize = 0;
    m_stReadChunkSize = 0;
    m_stBufferedDataSize = 0;
    m_stCurPos = 0;
    m_hFile = nullptr;
}

int CFileReader::Init (size_t stReadChunkSize)
{
	m_stReadChunkSize = stReadChunkSize;
	m_stBufferSize = m_stReadChunkSize * 2;
    m_pmbData = (uint8_t*) malloc(m_stBufferSize);
    if (m_pmbData == nullptr) {
		return -1;
	}

	return 0;
}

int CFileReader::OpenDataFile (SFileInfo * p_psoFileInfo)
{
    if (m_hFile != nullptr) {
		return -1;
	}
    strncpy(m_soFileInfo.m_mcDir, p_psoFileInfo->m_mcDir, sizeof(m_soFileInfo.m_mcDir));
    strncpy(m_soFileInfo.m_mcFileName, p_psoFileInfo->m_mcFileName, sizeof(m_soFileInfo.m_mcFileName));

    std::string strFileName(p_psoFileInfo->m_mcDir);
    strFileName += "/";
    strFileName += p_psoFileInfo->m_mcFileName;

    m_hFile = fopen(strFileName.c_str(), "r");
    if (m_hFile == nullptr) {
        return errno;
	}
	else {
		m_stBufferedDataSize = 0;
		m_stCurPos = 0;
		return 0;
	}
}

size_t CFileReader::ReadData(
    uint8_t  **p_ppmbData,
    size_t  bytesToRead)
{
    if (m_hFile == nullptr) {
		return 0;
	}
    if (0 == bytesToRead) {
		return 0;
	}

    if (m_stBufferedDataSize - m_stCurPos < bytesToRead) {
        if (0 != ReadDataFromFile (bytesToRead)) {
            *p_ppmbData = nullptr;
			return 0;
		}
	}

	*p_ppmbData = &(m_pmbData[m_stCurPos]);
    m_stCurPos += bytesToRead;

    return bytesToRead;
}


int CFileReader::CloseDataFile()
{
    if (m_hFile) {
        fclose(m_hFile);
        m_hFile = nullptr;
		return 0;
	}
	else {
		return -1;
	}
}



int CFileReader::ReadDataFromFile (size_t stRequestedDataSize)
{
    size_t readBytes;

	if (m_stCurPos + stRequestedDataSize > m_stBufferSize) {
        return -2;
	}
	if ( m_stBufferedDataSize == 0 || m_stCurPos > m_stReadChunkSize) {
        readBytes = fread(m_pmbData, sizeof(uint8_t), m_stReadChunkSize, m_hFile);
        if (readBytes < stRequestedDataSize) {
			return -1;
		}
		m_stCurPos = 0;
        m_stBufferedDataSize = readBytes;
	}
	else {
        size_t bytesToRead = stRequestedDataSize - m_stBufferedDataSize + m_stCurPos;
        readBytes = fread(&(m_pmbData[m_stBufferedDataSize]), sizeof(uint8_t), bytesToRead, m_hFile);
        if (bytesToRead != readBytes) {
            return -1;
		}
        m_stBufferedDataSize += readBytes;
	}
	
	return 0;
}


CFileReader::~CFileReader(void)
{
    if (m_pmbData != nullptr) {
        free(m_pmbData);
    }
    if (m_hFile != nullptr) {
        fclose(m_hFile);
    }
}
