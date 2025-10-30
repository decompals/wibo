#pragma once

#include "types.h"
#include "minwinbase.h"

struct TIME_ZONE_INFORMATION {
	LONG Bias;
	WCHAR StandardName[32];
	SYSTEMTIME StandardDate;
	LONG StandardBias;
	WCHAR DaylightName[32];
	SYSTEMTIME DaylightDate;
	LONG DaylightBias;
};

using LPTIME_ZONE_INFORMATION = TIME_ZONE_INFORMATION *;

constexpr DWORD TIME_ZONE_ID_UNKNOWN = 0;
constexpr DWORD TIME_ZONE_ID_STANDARD = 1;
constexpr DWORD TIME_ZONE_ID_DAYLIGHT = 2;
constexpr DWORD TIME_ZONE_ID_INVALID = 0xFFFFFFFFu;

namespace kernel32 {

BOOL WINAPI SystemTimeToFileTime(const SYSTEMTIME *lpSystemTime, LPFILETIME lpFileTime);
BOOL WINAPI FileTimeToSystemTime(const FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
BOOL WINAPI FileTimeToLocalFileTime(const FILETIME *lpFileTime, LPFILETIME lpLocalFileTime);
BOOL WINAPI LocalFileTimeToFileTime(const FILETIME *lpLocalFileTime, LPFILETIME lpFileTime);
BOOL WINAPI DosDateTimeToFileTime(WORD wFatDate, WORD wFatTime, LPFILETIME lpFileTime);
BOOL WINAPI FileTimeToDosDateTime(const FILETIME *lpFileTime, LPWORD lpFatDate, LPWORD lpFatTime);
DWORD WINAPI GetTimeZoneInformation(LPTIME_ZONE_INFORMATION lpTimeZoneInformation);

} // namespace kernel32
