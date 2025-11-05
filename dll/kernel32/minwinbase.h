#pragma once

#include "types.h"

struct SECURITY_ATTRIBUTES {
	DWORD nLength;
	GUEST_PTR lpSecurityDescriptor;
	BOOL bInheritHandle;
};

using PSECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES *;
using LPSECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES *;

struct FILETIME {
	DWORD dwLowDateTime;
	DWORD dwHighDateTime;
};

using PFILETIME = FILETIME *;
using LPFILETIME = FILETIME *;

struct SYSTEMTIME {
	WORD wYear;
	WORD wMonth;
	WORD wDayOfWeek;
	WORD wDay;
	WORD wHour;
	WORD wMinute;
	WORD wSecond;
	WORD wMilliseconds;
};

using PSYSTEMTIME = SYSTEMTIME *;
using LPSYSTEMTIME = SYSTEMTIME *;

enum FINDEX_INFO_LEVELS { FindExInfoStandard, FindExInfoBasic, FindExInfoMaxInfoLevel };

enum FINDEX_SEARCH_OPS {
	FindExSearchNameMatch,
	FindExSearchLimitToDirectories,
	FindExSearchLimitToDevices,
	FindExSearchMaxSearchOp
};

constexpr DWORD FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
constexpr DWORD FILE_ATTRIBUTE_NORMAL = 0x00000080;

constexpr DWORD MAX_PATH = 260;

struct WIN32_FIND_DATAA {
	DWORD dwFileAttributes;
	FILETIME ftCreationTime;
	FILETIME ftLastAccessTime;
	FILETIME ftLastWriteTime;
	DWORD nFileSizeHigh;
	DWORD nFileSizeLow;
	DWORD dwReserved0;
	DWORD dwReserved1;
	CHAR cFileName[MAX_PATH];
	CHAR cAlternateFileName[14];
};

struct WIN32_FIND_DATAW {
	DWORD dwFileAttributes;
	FILETIME ftCreationTime;
	FILETIME ftLastAccessTime;
	FILETIME ftLastWriteTime;
	DWORD nFileSizeHigh;
	DWORD nFileSizeLow;
	DWORD dwReserved0;
	DWORD dwReserved1;
	WCHAR cFileName[MAX_PATH];
	WCHAR cAlternateFileName[14];
};

using PWIN32_FIND_DATAA = WIN32_FIND_DATAA *;
using LPWIN32_FIND_DATAA = WIN32_FIND_DATAA *;
using PWIN32_FIND_DATAW = WIN32_FIND_DATAW *;
using LPWIN32_FIND_DATAW = WIN32_FIND_DATAW *;

typedef struct _OVERLAPPED {
	ULONG_PTR Internal;
	ULONG_PTR InternalHigh;
	union {
		struct {
			DWORD Offset;
			DWORD OffsetHigh;
		};
		GUEST_PTR Pointer;
	};
	HANDLE hEvent;
} OVERLAPPED, *LPOVERLAPPED;
