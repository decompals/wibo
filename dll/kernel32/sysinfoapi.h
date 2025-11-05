#pragma once

#include "minwinbase.h"
#include "types.h"

struct SYSTEM_INFO {
	union {
		DWORD dwOemId;
		struct {
			WORD wProcessorArchitecture;
			WORD wReserved;
		};
	};
	DWORD dwPageSize;
	GUEST_PTR lpMinimumApplicationAddress;
	GUEST_PTR lpMaximumApplicationAddress;
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

struct OSVERSIONINFOW {
	DWORD dwOSVersionInfoSize;
	DWORD dwMajorVersion;
	DWORD dwMinorVersion;
	DWORD dwBuildNumber;
	DWORD dwPlatformId;
	WCHAR szCSDVersion[128];
};

using LPOSVERSIONINFOW = OSVERSIONINFOW *;

struct OSVERSIONINFOEXA : OSVERSIONINFOA {
	WORD wServicePackMajor;
	WORD wServicePackMinor;
	WORD wSuiteMask;
	BYTE wProductType;
	BYTE wReserved;
};

using LPOSVERSIONINFOEXA = OSVERSIONINFOEXA *;

struct OSVERSIONINFOEXW : OSVERSIONINFOW {
	WORD wServicePackMajor;
	WORD wServicePackMinor;
	WORD wSuiteMask;
	BYTE wProductType;
	BYTE wReserved;
};

using LPOSVERSIONINFOEXW = OSVERSIONINFOEXW *;

namespace kernel32 {

void WINAPI GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);
void WINAPI GetSystemTime(LPSYSTEMTIME lpSystemTime);
void WINAPI GetLocalTime(LPSYSTEMTIME lpSystemTime);
void WINAPI GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime);
DWORD WINAPI GetTickCount();
DWORD WINAPI GetVersion();
BOOL WINAPI GetVersionExA(LPOSVERSIONINFOA lpVersionInformation);
BOOL WINAPI GetVersionExW(LPOSVERSIONINFOW lpVersionInformation);

} // namespace kernel32
