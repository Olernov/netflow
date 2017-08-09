#include "FileWriter.h"
#include <string.h>
#include <libgen.h>

int CFileWriter::Init (size_t p_stBufSize)
{
	m_stBufSize = p_stBufSize;
    m_pmbBuf = new uint8_t[m_stBufSize];

	return 0;
}

int CFileWriter::CreateOutputFile(char *pszFileName, bool bRewriteFile)
{
    if (pszFileName == nullptr) {
		return -1;
	}
    if (m_hFile != nullptr) {
		return -1;
	}

    char mcFileName[MAX_PATH];
    strncpy(mcFileName, pszFileName, sizeof(mcFileName));

    if (bRewriteFile) {
        m_hFile = fopen(mcFileName, "w");
    }
    else {
        short attemptCounter = 0;
        while (++attemptCounter < 256) {
            m_hFile = fopen(mcFileName, "r");
            if (m_hFile == nullptr) {
                m_hFile = fopen(mcFileName, "w");
                break;
            }
            else {
                fclose(m_hFile);
            }
            sprintf(mcFileName, "%s.%03u", pszFileName, attemptCounter);
        }
    }

    return (m_hFile == nullptr ? -1 : 0) ;
}

int CFileWriter::WriteData(
    uint8_t *p_bpData,
	size_t p_stDataSize)
{
    if (m_hFile == nullptr) {
		return -1;
	}
    if (m_pmbBuf == nullptr) {
		return -1;
	}

    size_t stuint8_tsToCopy;
	size_t stDataReadInd;

	stDataReadInd = 0;
    stuint8_tsToCopy = 0;

	while (stDataReadInd < p_stDataSize) {
		if (m_stCurPos == m_stBufSize) {
			if (! Finalise()) {
				return -1;
			}
		}
        stuint8_tsToCopy = m_stBufSize - m_stCurPos > p_stDataSize - stDataReadInd ?
			p_stDataSize - stDataReadInd
			: m_stBufSize - m_stCurPos;
        if (stuint8_tsToCopy) {
			memcpy(
				&(m_pmbBuf[m_stCurPos]),
				&(p_bpData[stDataReadInd]),
                stuint8_tsToCopy);
            stDataReadInd += stuint8_tsToCopy;
            m_stCurPos += stuint8_tsToCopy;
		}
	}

	return 0;
}

int CFileWriter::Finalise()
{
    size_t uint8_tsWritten;

    if (m_hFile == nullptr) {
		return -1;
	}
	if (m_stCurPos) {
        uint8_tsWritten = fwrite(m_pmbBuf, sizeof(uint8_t), m_stCurPos, m_hFile);
        if (uint8_tsWritten != m_stCurPos /*(size_t)dwuint8_tsWritten*/) {
			return -1;
		}
		m_stCurPos = 0;
	}

	return 0;
}

CFileWriter::CFileWriter(void)
{
    m_pmbBuf = nullptr;
	m_stBufSize = 0;
	m_stCurPos = 0;
    m_hFile = nullptr;
}

CFileWriter::~CFileWriter(void)
{
	if (m_pmbBuf) {
		delete[] m_pmbBuf;
        m_pmbBuf = nullptr;
	}
	m_stBufSize = 0;
	m_stCurPos = 0;
    if (m_hFile != nullptr) {
        fclose (m_hFile);
        m_hFile = nullptr;
	}
}
