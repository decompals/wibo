#pragma once

#include "minwinbase.h"

#include <cstdint>
#include <ctime>
#include <limits>

inline constexpr int64_t HUNDRED_NS_PER_SECOND = 10000000LL;
inline constexpr int64_t HUNDRED_NS_PER_MILLISECOND = 10000LL;
inline constexpr int64_t SECONDS_PER_DAY = 86400LL;
inline constexpr uint64_t TICKS_PER_DAY = static_cast<uint64_t>(SECONDS_PER_DAY) * HUNDRED_NS_PER_SECOND;
inline constexpr uint64_t UNIX_TIME_ZERO = 11644473600ULL * 10000000ULL;
inline constexpr uint64_t MAX_VALID_FILETIME = 0x8000000000000000ULL;
inline constexpr int64_t DAYS_TO_UNIX_EPOCH = 134774LL;

struct CivilDate {
	int year;
	unsigned month;
	unsigned day;
};

inline int64_t daysFromCivil(int year, unsigned month, unsigned day) {
	year -= month <= 2 ? 1 : 0;
	const int era = (year >= 0 ? year : year - 399) / 400;
	const unsigned yoe = static_cast<unsigned>(year - era * 400);
	const unsigned doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
	const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + yoe / 400 + doy;
	return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

inline CivilDate civilFromDays(int64_t z) {
	z += 719468;
	const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
	const unsigned doe = static_cast<unsigned>(z - era * 146097);
	const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	const int64_t y = static_cast<int64_t>(yoe) + era * 400;
	const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	const unsigned mp = (5 * doy + 2) / 153;
	const unsigned d = doy - (153 * mp + 2) / 5 + 1;
	const unsigned m = mp + (mp < 10 ? 3 : -9);
	return {static_cast<int>(y + (m <= 2)), m, d};
}

inline bool isLeapYear(int year) {
	if ((year % 4) != 0) {
		return false;
	}
	if ((year % 100) != 0) {
		return true;
	}
	return (year % 400) == 0;
}

inline unsigned daysInMonth(int year, unsigned month) {
	static const unsigned baseDays[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
	unsigned idx = month - 1;
	unsigned value = baseDays[idx];
	if (month == 2 && isLeapYear(year)) {
		value += 1;
	}
	return value;
}

inline bool validateSystemTime(const SYSTEMTIME &st) {
	if (st.wYear < 1601) {
		return false;
	}
	if (st.wMonth < 1 || st.wMonth > 12) {
		return false;
	}
	if (st.wDay < 1 || st.wDay > static_cast<short>(daysInMonth(st.wYear, static_cast<unsigned>(st.wMonth)))) {
		return false;
	}
	if (st.wHour > 23) {
		return false;
	}
	if (st.wMinute > 59) {
		return false;
	}
	if (st.wSecond > 59) {
		return false;
	}
	if (st.wMilliseconds > 999) {
		return false;
	}
	return true;
}

inline bool systemTimeToUnixParts(const SYSTEMTIME &st, int64_t &secondsOut, uint32_t &hundredsOut) {
	if (!validateSystemTime(st)) {
		return false;
	}
	int64_t days = daysFromCivil(st.wYear, static_cast<unsigned>(st.wMonth), static_cast<unsigned>(st.wDay));
	int64_t secondsOfDay =
		static_cast<int64_t>(st.wHour) * 3600LL + static_cast<int64_t>(st.wMinute) * 60LL + st.wSecond;
	secondsOut = days * SECONDS_PER_DAY + secondsOfDay;
	hundredsOut = static_cast<uint32_t>(st.wMilliseconds) * static_cast<uint32_t>(HUNDRED_NS_PER_MILLISECOND);
	return true;
}

inline uint64_t fileTimeToDuration(const FILETIME &value) {
	return (static_cast<uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}

inline bool fileTimeToUnixParts(const FILETIME &ft, int64_t &secondsOut, uint32_t &hundredsOut) {
	uint64_t ticks = fileTimeToDuration(ft);
	if (ticks >= UNIX_TIME_ZERO) {
		uint64_t diff = ticks - UNIX_TIME_ZERO;
		secondsOut = static_cast<int64_t>(diff / HUNDRED_NS_PER_SECOND);
		hundredsOut = static_cast<uint32_t>(diff % HUNDRED_NS_PER_SECOND);
	} else {
		uint64_t diff = UNIX_TIME_ZERO - ticks;
		secondsOut = -static_cast<int64_t>(diff / HUNDRED_NS_PER_SECOND);
		uint64_t rem = diff % HUNDRED_NS_PER_SECOND;
		if (rem != 0) {
			secondsOut -= 1;
			rem = HUNDRED_NS_PER_SECOND - rem;
		}
		hundredsOut = static_cast<uint32_t>(rem);
	}
	return true;
}

inline FILETIME fileTimeFromDuration(uint64_t ticks100ns) {
	FILETIME result;
	result.dwLowDateTime = static_cast<DWORD>(ticks100ns & 0xFFFFFFFFULL);
	result.dwHighDateTime = static_cast<DWORD>(ticks100ns >> 32);
	return result;
}

inline bool unixPartsToFileTime(int64_t seconds, uint32_t hundreds, FILETIME &out) {
	if (hundreds >= HUNDRED_NS_PER_SECOND) {
		return false;
	}
#if defined(__SIZEOF_INT128__)
	__int128 total = static_cast<__int128>(seconds) * HUNDRED_NS_PER_SECOND;
	total += static_cast<__int128>(hundreds);
	total += static_cast<__int128>(UNIX_TIME_ZERO);
	if (total < 0 || total > static_cast<__int128>(std::numeric_limits<uint64_t>::max())) {
		return false;
	}
	uint64_t ticks = static_cast<uint64_t>(total);
#else
	long double total = static_cast<long double>(seconds) * static_cast<long double>(HUNDRED_NS_PER_SECOND);
	total += static_cast<long double>(hundreds);
	total += static_cast<long double>(UNIX_TIME_ZERO);
	if (total < 0.0L || total > static_cast<long double>(std::numeric_limits<uint64_t>::max())) {
		return false;
	}
	uint64_t ticks = static_cast<uint64_t>(total);
#endif
	out = fileTimeFromDuration(ticks);
	return true;
}

inline bool unixPartsToTimespec(int64_t seconds, uint32_t hundreds, struct timespec &out) {
	if (hundreds >= HUNDRED_NS_PER_SECOND) {
		return false;
	}
	if (seconds > static_cast<int64_t>(std::numeric_limits<time_t>::max()) ||
		seconds < static_cast<int64_t>(std::numeric_limits<time_t>::min())) {
		return false;
	}
	out.tv_sec = static_cast<time_t>(seconds);
	out.tv_nsec = static_cast<long>(hundreds) * 100L;
	return true;
}

inline bool tmToUnixSeconds(const struct tm &tmValue, int64_t &secondsOut) {
	int year = tmValue.tm_year + 1900;
	int month = tmValue.tm_mon + 1;
	int day = tmValue.tm_mday;
	int hour = tmValue.tm_hour;
	int minute = tmValue.tm_min;
	int second = tmValue.tm_sec;
	if (month < 1 || month > 12) {
		return false;
	}
	if (day < 1 || day > static_cast<int>(daysInMonth(year, static_cast<unsigned>(month)))) {
		return false;
	}
	if (hour < 0 || hour > 23) {
		return false;
	}
	if (minute < 0 || minute > 59) {
		return false;
	}
	if (second < 0 || second > 60) {
		return false;
	}
	if (second == 60) {
		second = 59;
	}
	int64_t days = daysFromCivil(year, static_cast<unsigned>(month), static_cast<unsigned>(day));
	secondsOut =
		days * SECONDS_PER_DAY + static_cast<int64_t>(hour) * 3600LL + static_cast<int64_t>(minute) * 60LL + second;
	return true;
}

inline bool shouldIgnoreFileTimeParam(const FILETIME *ft) {
	if (!ft) {
		return true;
	}
	if (ft->dwLowDateTime == 0 && ft->dwHighDateTime == 0) {
		return true;
	}
	if (ft->dwLowDateTime == 0xFFFFFFFF && ft->dwHighDateTime == 0xFFFFFFFF) {
		return true;
	}
	return false;
}
