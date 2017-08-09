#pragma once
#include <stdio.h>
#include <stdint.h>
#include "common.h"

class CFileWriter
{
public:
	int Init (size_t p_stBufSize);
    int CreateOutputFile(char *p_pszFileName, bool bRewriteFile = false);
    int WriteData(uint8_t *p_bpData, size_t p_stDataSize);
	int Finalise();
public:
	CFileWriter(void);
	~CFileWriter(void);
private:
    uint8_t *m_pmbBuf;
	size_t m_stBufSize;
	size_t m_stCurPos;
    FILE* m_hFile;
};
