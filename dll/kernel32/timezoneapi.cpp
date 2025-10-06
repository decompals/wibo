#include "timezoneapi.h"

#include "context.h"
#include "errors.h"
#include "timeutil.h"

#include <cerrno>
#include <cstring>
#include <ctime>

namespace kernel32 {

BOOL WIN_FUNC SystemTimeToFileTime(const SYSTEMTIME *lpSystemTime, LPFILETIME lpFileTime) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SystemTimeToFileTime(%p, %p)\n", lpSystemTime, lpFileTime);
	if (!lpSystemTime || !lpFileTime) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	int64_t seconds = 0;
	uint32_t hundreds = 0;
	if (!systemTimeToUnixParts(*lpSystemTime, seconds, hundreds)) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	FILETIME result;
	if (!unixPartsToFileTime(seconds, hundreds, result)) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	if (fileTimeToDuration(result) >= MAX_VALID_FILETIME) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	*lpFileTime = result;
	return TRUE;
}

BOOL WIN_FUNC FileTimeToSystemTime(const FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FileTimeToSystemTime(%p, %p)\n", lpFileTime, lpSystemTime);
	if (!lpFileTime || !lpSystemTime) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	uint64_t ticks = fileTimeToDuration(*lpFileTime);
	if (ticks >= MAX_VALID_FILETIME) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	uint64_t daysSince1601 = ticks / TICKS_PER_DAY;
	uint64_t ticksOfDay = ticks % TICKS_PER_DAY;
	uint32_t secondsOfDay = static_cast<uint32_t>(ticksOfDay / HUNDRED_NS_PER_SECOND);
	uint32_t hundredNs = static_cast<uint32_t>(ticksOfDay % HUNDRED_NS_PER_SECOND);
	int64_t daysSince1970 = static_cast<int64_t>(daysSince1601) - DAYS_TO_UNIX_EPOCH;
	CivilDate date = civilFromDays(daysSince1970);
	lpSystemTime->wYear = static_cast<WORD>(date.year);
	lpSystemTime->wMonth = static_cast<WORD>(date.month);
	lpSystemTime->wDay = static_cast<WORD>(date.day);
	lpSystemTime->wDayOfWeek = static_cast<WORD>((daysSince1601 + 1ULL) % 7ULL);
	lpSystemTime->wHour = static_cast<WORD>(secondsOfDay / 3600U);
	lpSystemTime->wMinute = static_cast<WORD>((secondsOfDay % 3600U) / 60U);
	lpSystemTime->wSecond = static_cast<WORD>(secondsOfDay % 60U);
	lpSystemTime->wMilliseconds = static_cast<WORD>(hundredNs / HUNDRED_NS_PER_MILLISECOND);
	return TRUE;
}

BOOL WIN_FUNC FileTimeToLocalFileTime(const FILETIME *lpFileTime, LPFILETIME lpLocalFileTime) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FileTimeToLocalFileTime(%p, %p)\n", lpFileTime, lpLocalFileTime);
	if (!lpFileTime || !lpLocalFileTime) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	int64_t seconds = 0;
	uint32_t hundreds = 0;
	if (!fileTimeToUnixParts(*lpFileTime, seconds, hundreds)) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	if (seconds > static_cast<int64_t>(std::numeric_limits<time_t>::max()) ||
		seconds < static_cast<int64_t>(std::numeric_limits<time_t>::min())) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	time_t unixTime = static_cast<time_t>(seconds);
	struct tm localTm{};
#if defined(_POSIX_VERSION)
	if (!localtime_r(&unixTime, &localTm)) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
#else
	struct tm *tmp = localtime(&unixTime);
	if (!tmp) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	localTm = *tmp;
#endif
	int64_t localAsUtcSeconds = 0;
	if (!tmToUnixSeconds(localTm, localAsUtcSeconds)) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	int64_t offsetSeconds = localAsUtcSeconds - seconds;
	int64_t localSeconds = seconds + offsetSeconds;
	FILETIME result;
	if (!unixPartsToFileTime(localSeconds, hundreds, result)) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	*lpLocalFileTime = result;
	return TRUE;
}

BOOL WIN_FUNC LocalFileTimeToFileTime(const FILETIME *lpLocalFileTime, LPFILETIME lpFileTime) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("LocalFileTimeToFileTime(%p, %p)\n", lpLocalFileTime, lpFileTime);
	if (!lpLocalFileTime || !lpFileTime) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	uint64_t ticks = fileTimeToDuration(*lpLocalFileTime);
	if (ticks >= MAX_VALID_FILETIME) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	uint32_t hundredNs = static_cast<uint32_t>(ticks % HUNDRED_NS_PER_SECOND);
	uint64_t daysSince1601 = ticks / TICKS_PER_DAY;
	uint64_t ticksOfDay = ticks % TICKS_PER_DAY;
	uint32_t secondsOfDay = static_cast<uint32_t>(ticksOfDay / HUNDRED_NS_PER_SECOND);
	int64_t daysSince1970 = static_cast<int64_t>(daysSince1601) - DAYS_TO_UNIX_EPOCH;
	CivilDate date = civilFromDays(daysSince1970);
	struct tm localTm{};
	localTm.tm_year = date.year - 1900;
	localTm.tm_mon = static_cast<int>(date.month) - 1;
	localTm.tm_mday = static_cast<int>(date.day);
	localTm.tm_hour = static_cast<int>(secondsOfDay / 3600U);
	localTm.tm_min = static_cast<int>((secondsOfDay % 3600U) / 60U);
	localTm.tm_sec = static_cast<int>(secondsOfDay % 60U);
	localTm.tm_isdst = -1;
	struct tm tmCopy = localTm;
	errno = 0;
	time_t utcTime = mktime(&tmCopy);
	if (utcTime == static_cast<time_t>(-1) && errno != 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	FILETIME result;
	if (!unixPartsToFileTime(static_cast<int64_t>(utcTime), hundredNs, result)) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	*lpFileTime = result;
	return TRUE;
}

BOOL WIN_FUNC DosDateTimeToFileTime(WORD wFatDate, WORD wFatTime, LPFILETIME lpFileTime) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("DosDateTimeToFileTime(%04x, %04x, %p)\n", wFatDate, wFatTime, lpFileTime);
	if (!lpFileTime) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	unsigned day = wFatDate & 0x1F;
	unsigned month = (wFatDate >> 5) & 0x0F;
	unsigned year = ((wFatDate >> 9) & 0x7F) + 1980;
	unsigned second = (wFatTime & 0x1F) * 2;
	unsigned minute = (wFatTime >> 5) & 0x3F;
	unsigned hour = (wFatTime >> 11) & 0x1F;
	if (day == 0 || month == 0 || month > 12 || day > 31 || hour > 23 || minute > 59 || second > 59) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	struct tm tmValue{};
	tmValue.tm_year = static_cast<int>(year) - 1900;
	tmValue.tm_mon = static_cast<int>(month) - 1;
	tmValue.tm_mday = static_cast<int>(day);
	tmValue.tm_hour = static_cast<int>(hour);
	tmValue.tm_min = static_cast<int>(minute);
	tmValue.tm_sec = static_cast<int>(second);
	tmValue.tm_isdst = -1;
	time_t localSeconds = mktime(&tmValue);
	if (localSeconds == static_cast<time_t>(-1)) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	uint64_t ticks = (static_cast<uint64_t>(localSeconds) + UNIX_TIME_ZERO / HUNDRED_NS_PER_SECOND) * 10000000ULL;
	*lpFileTime = fileTimeFromDuration(ticks);
	return TRUE;
}

BOOL WIN_FUNC FileTimeToDosDateTime(const FILETIME *lpFileTime, LPWORD lpFatDate, LPWORD lpFatTime) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FileTimeToDosDateTime(%p, %p, %p)\n", lpFileTime, lpFatDate, lpFatTime);
	if (!lpFileTime || !lpFatDate || !lpFatTime) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	uint64_t ticks = fileTimeToDuration(*lpFileTime);
	if (ticks < UNIX_TIME_ZERO) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	time_t utcSeconds = static_cast<time_t>((ticks / 10000000ULL) - (UNIX_TIME_ZERO / HUNDRED_NS_PER_SECOND));
	struct tm tmValue{};
	if (!localtime_r(&utcSeconds, &tmValue)) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	int year = tmValue.tm_year + 1900;
	if (year < 1980 || year > 2107) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	*lpFatDate = static_cast<WORD>(((year - 1980) << 9) | ((tmValue.tm_mon + 1) << 5) | tmValue.tm_mday);
	*lpFatTime = static_cast<WORD>(((tmValue.tm_hour & 0x1F) << 11) | ((tmValue.tm_min & 0x3F) << 5) |
								   ((tmValue.tm_sec / 2) & 0x1F));
	return TRUE;
}

DWORD WIN_FUNC GetTimeZoneInformation(LPTIME_ZONE_INFORMATION lpTimeZoneInformation) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetTimeZoneInformation(%p)\n", lpTimeZoneInformation);
	if (!lpTimeZoneInformation) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return TIME_ZONE_ID_INVALID;
	}
	std::memset(lpTimeZoneInformation, 0, sizeof(*lpTimeZoneInformation));
	tzset();
	auto copyName = [](WCHAR *dest, const char *src) {
		if (!src) {
			dest[0] = 0;
			return;
		}
		for (size_t i = 0; i < 31 && src[i]; ++i) {
			dest[i] = static_cast<unsigned char>(src[i]);
			dest[i + 1] = 0;
		}
	};
	time_t now = time(nullptr);
	struct tm localTm{};
#if defined(_GNU_SOURCE) || defined(__APPLE__)
	localtime_r(&now, &localTm);
#else
	struct tm *tmp = localtime(&now);
	if (tmp) {
		localTm = *tmp;
	}
#endif
	long offsetSeconds = 0;
#if defined(__APPLE__) || defined(__linux__)
	offsetSeconds = -localTm.tm_gmtoff;
#else
	extern long timezone;
	offsetSeconds = timezone;
	if (localTm.tm_isdst > 0) {
		extern int daylight;
		if (daylight) {
			offsetSeconds -= 3600;
		}
	}
#endif
	lpTimeZoneInformation->Bias = static_cast<LONG>(offsetSeconds / 60);
	copyName(lpTimeZoneInformation->StandardName, tzname[0]);
	const char *daylightName = (daylight && tzname[1]) ? tzname[1] : tzname[0];
	copyName(lpTimeZoneInformation->DaylightName, daylightName);
	DWORD result = TIME_ZONE_ID_UNKNOWN;
	if (daylight && localTm.tm_isdst > 0) {
		lpTimeZoneInformation->DaylightBias = -60;
		result = TIME_ZONE_ID_DAYLIGHT;
	} else {
		result = TIME_ZONE_ID_STANDARD;
	}
	return result;
}

} // namespace kernel32
