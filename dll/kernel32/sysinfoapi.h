#pragma once

#include "common.h"
#include "minwinbase.h"

struct SYSTEM_INFO {
	union {
		DWORD dwOemId;
		struct {
			WORD wProcessorArchitecture;
			WORD wReserved;
		};
	};
	DWORD dwPageSize;
	LPVOID lpMinimumApplicationAddress;
	LPVOID lpMaximumApplicationAddress;
	DWORD_PTR dwActiveProcessorMask;
	DWORD dwNumberOfProcessors;
	DWORD dwProcessorType;
	DWORD dwAllocationGranularity;
	WORD wProcessorLevel;
	WORD wProcessorRevision;
};

using LPSYSTEM_INFO = SYSTEM_INFO *;

struct OSVERSIONINFOA {
	DWORD dwOSVersionInfoSize;
	DWORD dwMajorVersion;
	DWORD dwMinorVersion;
	DWORD dwBuildNumber;
	DWORD dwPlatformId;
	char szCSDVersion[128];
};

using LPOSVERSIONINFOA = OSVERSIONINFOA *;

namespace kernel32 {

void WIN_FUNC GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
void WIN_FUNC GetSystemTime(LPSYSTEMTIME lpSystemTime);
void WIN_FUNC GetLocalTime(LPSYSTEMTIME lpSystemTime);
void WIN_FUNC GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime);
DWORD WIN_FUNC GetTickCount();
DWORD WIN_FUNC GetVersion();
BOOL WIN_FUNC GetVersionExA(LPOSVERSIONINFOA lpVersionInformation);

} // namespace kernel32
