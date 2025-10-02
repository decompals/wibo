#include "sysinfoapi.h"
#include "common.h"
#include "errors.h"
#include "timeutil.h"

#include <cstring>
#include <ctime>
#include <sys/time.h>

namespace {

constexpr WORD PROCESSOR_ARCHITECTURE_INTEL = 0;
constexpr DWORD PROCESSOR_INTEL_PENTIUM = 586;

constexpr uint64_t kUnixTimeZero = 11644473600ULL * 10000000ULL;
constexpr DWORD kMajorVersion = 6;
constexpr DWORD kMinorVersion = 2;
constexpr DWORD kBuildNumber = 0;

DWORD_PTR computeSystemProcessorMask(unsigned int cpuCount) {
	const auto maskWidth = static_cast<unsigned int>(sizeof(DWORD_PTR) * 8);
	if (cpuCount >= maskWidth) {
		return static_cast<DWORD_PTR>(~static_cast<DWORD_PTR>(0));
	}
	DWORD_PTR mask = (static_cast<DWORD_PTR>(1) << cpuCount) - 1;
	return mask == 0 ? 1 : mask;
}

} // namespace

namespace kernel32 {

void WIN_FUNC GetSystemInfo(LPSYSTEM_INFO lpSystemInfo) {
	DEBUG_LOG("GetSystemInfo(%p)\n", lpSystemInfo);
	if (!lpSystemInfo) {
		return;
	}

	std::memset(lpSystemInfo, 0, sizeof(*lpSystemInfo));
	lpSystemInfo->wProcessorArchitecture = PROCESSOR_ARCHITECTURE_INTEL;
	lpSystemInfo->dwOemId = lpSystemInfo->wProcessorArchitecture;
	lpSystemInfo->dwProcessorType = PROCESSOR_INTEL_PENTIUM;
	lpSystemInfo->wProcessorLevel = 6; // Pentium

	long pageSize = sysconf(_SC_PAGESIZE);
	if (pageSize <= 0) {
		pageSize = 4096;
	}
	lpSystemInfo->dwPageSize = static_cast<DWORD>(pageSize);

	lpSystemInfo->lpMinimumApplicationAddress = reinterpret_cast<LPVOID>(0x00010000);
	if (sizeof(void *) == 4) {
		lpSystemInfo->lpMaximumApplicationAddress = reinterpret_cast<LPVOID>(0x7FFEFFFF);
	} else {
		lpSystemInfo->lpMaximumApplicationAddress = reinterpret_cast<LPVOID>(0x00007FFFFFFEFFFFull);
	}

	unsigned int cpuCount = 1;
	long reported = sysconf(_SC_NPROCESSORS_ONLN);
	if (reported > 0) {
		cpuCount = static_cast<unsigned int>(reported);
	}
	lpSystemInfo->dwNumberOfProcessors = cpuCount;
	lpSystemInfo->dwActiveProcessorMask = computeSystemProcessorMask(cpuCount);

	lpSystemInfo->dwAllocationGranularity = 0x10000;
}

void WIN_FUNC GetSystemTime(LPSYSTEMTIME lpSystemTime) {
	DEBUG_LOG("GetSystemTime(%p)\n", lpSystemTime);
	if (!lpSystemTime) {
		return;
	}

	time_t now = time(nullptr);
	struct tm tmUtc{};
#if defined(_GNU_SOURCE) || defined(__APPLE__)
	gmtime_r(&now, &tmUtc);
#else
	struct tm *tmp = gmtime(&now);
	if (!tmp) {
		return;
	}
	tmUtc = *tmp;
#endif

	lpSystemTime->wYear = static_cast<WORD>(tmUtc.tm_year + 1900);
	lpSystemTime->wMonth = static_cast<WORD>(tmUtc.tm_mon + 1);
	lpSystemTime->wDayOfWeek = static_cast<WORD>(tmUtc.tm_wday);
	lpSystemTime->wDay = static_cast<WORD>(tmUtc.tm_mday);
	lpSystemTime->wHour = static_cast<WORD>(tmUtc.tm_hour);
	lpSystemTime->wMinute = static_cast<WORD>(tmUtc.tm_min);
	lpSystemTime->wSecond = static_cast<WORD>(tmUtc.tm_sec);
	lpSystemTime->wMilliseconds = 0;
}

void WIN_FUNC GetLocalTime(LPSYSTEMTIME lpSystemTime) {
	DEBUG_LOG("GetLocalTime(%p)\n", lpSystemTime);
	if (!lpSystemTime) {
		return;
	}

	time_t now = time(nullptr);
	struct tm tmLocal{};
#if defined(_GNU_SOURCE) || defined(__APPLE__)
	localtime_r(&now, &tmLocal);
#else
	struct tm *tmp = localtime(&now);
	if (!tmp) {
		return;
	}
	tmLocal = *tmp;
#endif

	lpSystemTime->wYear = static_cast<WORD>(tmLocal.tm_year + 1900);
	lpSystemTime->wMonth = static_cast<WORD>(tmLocal.tm_mon + 1);
	lpSystemTime->wDayOfWeek = static_cast<WORD>(tmLocal.tm_wday);
	lpSystemTime->wDay = static_cast<WORD>(tmLocal.tm_mday);
	lpSystemTime->wHour = static_cast<WORD>(tmLocal.tm_hour);
	lpSystemTime->wMinute = static_cast<WORD>(tmLocal.tm_min);
	lpSystemTime->wSecond = static_cast<WORD>(tmLocal.tm_sec);
	lpSystemTime->wMilliseconds = 0;
}

void WIN_FUNC GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime) {
	DEBUG_LOG("GetSystemTimeAsFileTime(%p)\n", lpSystemTimeAsFileTime);
	if (!lpSystemTimeAsFileTime) {
		return;
	}

#if defined(CLOCK_REALTIME)
	struct timespec ts{};
	if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
		uint64_t ticks = kUnixTimeZero;
		ticks += static_cast<uint64_t>(ts.tv_sec) * 10000000ULL;
		ticks += static_cast<uint64_t>(ts.tv_nsec) / 100ULL;
		*lpSystemTimeAsFileTime = fileTimeFromDuration(ticks);
		return;
	}
#endif

	struct timeval tv{};
	if (gettimeofday(&tv, nullptr) == 0) {
		uint64_t ticks = kUnixTimeZero;
		ticks += static_cast<uint64_t>(tv.tv_sec) * 10000000ULL;
		ticks += static_cast<uint64_t>(tv.tv_usec) * 10ULL;
		*lpSystemTimeAsFileTime = fileTimeFromDuration(ticks);
		return;
	}

	const FILETIME fallback = {static_cast<DWORD>(kUnixTimeZero & 0xFFFFFFFFULL),
							   static_cast<DWORD>(kUnixTimeZero >> 32)};
	*lpSystemTimeAsFileTime = fallback;
}

DWORD WIN_FUNC GetTickCount() {
	DEBUG_LOG("GetTickCount()\n");
#if defined(CLOCK_MONOTONIC)
	struct timespec ts{};
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
		uint64_t milliseconds =
			static_cast<uint64_t>(ts.tv_sec) * 1000ULL + static_cast<uint64_t>(ts.tv_nsec) / 1000000ULL;
		DWORD result = static_cast<DWORD>(milliseconds & 0xFFFFFFFFULL);
		DEBUG_LOG(" -> %u\n", result);
		return result;
	}
#endif
	struct timeval tv{};
	if (gettimeofday(&tv, nullptr) == 0) {
		uint64_t milliseconds =
			static_cast<uint64_t>(tv.tv_sec) * 1000ULL + static_cast<uint64_t>(tv.tv_usec) / 1000ULL;
		DWORD result = static_cast<DWORD>(milliseconds & 0xFFFFFFFFULL);
		DEBUG_LOG(" -> %u\n", result);
		return result;
	}
	DEBUG_LOG(" -> 0\n");
	return 0;
}

DWORD WIN_FUNC GetVersion() {
	DEBUG_LOG("GetVersion()\n");
	return kMajorVersion | (kMinorVersion << 8) | (5 << 16) | (kBuildNumber << 24);
}

BOOL WIN_FUNC GetVersionExA(LPOSVERSIONINFOA lpVersionInformation) {
	DEBUG_LOG("GetVersionExA(%p)\n", lpVersionInformation);
	if (!lpVersionInformation) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	std::memset(lpVersionInformation, 0, lpVersionInformation->dwOSVersionInfoSize);
	lpVersionInformation->dwMajorVersion = kMajorVersion;
	lpVersionInformation->dwMinorVersion = kMinorVersion;
	lpVersionInformation->dwBuildNumber = kBuildNumber;
	lpVersionInformation->dwPlatformId = 2;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

} // namespace kernel32
