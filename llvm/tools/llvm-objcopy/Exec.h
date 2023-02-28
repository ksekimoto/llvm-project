#ifndef _EXEC_H
#define _EXEC_H

#ifdef _WIN32
    #include <windows.h>
#else
    typedef unsigned char BYTE;
#endif

#include <string>

//check if current line is preprocessor line containing line number and file information
bool IsPreprocLine(const BYTE *start, const BYTE *end, unsigned int &lineNumber, std::string &fileName, bool canStartWithComment = false);

//execute a compile command and waits for it to finish
bool RunCmd(const char *cmd, int &exitCode);

//same as RunCmd but using pipes/buffers as input/output rather than actual files
bool RunCmdOnBuffer(const char *cmd, int &exitCode, const BYTE *buffer, unsigned int bufferLengh, 
	std::string *errBuffer = 0, std::string *outBuffer = 0, bool emitLineStatements = true);

#endif //_EXEC_H
