#include "sysinfoapi.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "internal.h"
#include "ntdll.h"
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

constexpr DWORD VER_MINORVERSION = 0x0000001;
constexpr DWORD VER_MAJORVERSION = 0x0000002;
constexpr DWORD VER_BUILDNUMBER = 0x0000004;
constexpr DWORD VER_PLATFORMID = 0x0000008;
constexpr DWORD VER_SERVICEPACKMINOR = 0x0000010;
constexpr DWORD VER_SERVICEPACKMAJOR = 0x0000020;
constexpr DWORD VER_SUITENAME = 0x0000040;
constexpr DWORD VER_PRODUCT_TYPE = 0x0000080;

constexpr BYTE VER_EQUAL = 1;
constexpr BYTE VER_GREATER = 2;
constexpr BYTE VER_GREATER_EQUAL = 3;
constexpr BYTE VER_LESS = 4;
constexpr BYTE VER_LESS_EQUAL = 5;
constexpr BYTE VER_AND = 6;
constexpr BYTE VER_OR = 7;

BYTE conditionFor(ULONGLONG conditionMask, unsigned int slot) {
	return static_cast<BYTE>((conditionMask >> (slot * 3)) & 0x07);
}

bool compareValues(DWORD actual, DWORD expected, BYTE condition) {
	switch (condition) {
	case VER_EQUAL:
		return actual == expected;
	case VER_GREATER:
		return actual > expected;
	case VER_GREATER_EQUAL:
		return actual >= expected;
	case VER_LESS:
		return actual < expected;
	case VER_LESS_EQUAL:
		return actual <= expected;
	default:
		return false;
	}
}

bool compareMask(WORD actual, WORD expected, BYTE condition) {
	switch (condition) {
	case VER_AND:
		return (actual & expected) == expected;
	case VER_OR:
		return expected == 0 || (actual & expected) != 0;
	default:
		return false;
	}
}

} // namespace

namespace kernel32 {

void WINAPI GetSystemInfo(LPSYSTEM_INFO lpSystemInfo) {
	HOST_CONTEXT_GUARD();
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

	lpSystemInfo->lpMinimumApplicationAddress = toGuestPtr(reinterpret_cast<void *>(0x00010000));
#ifdef _WIN64
	lpSystemInfo->lpMaximumApplicationAddress = toGuestPtr(reinterpret_cast<void *>(0x00007FFFFFFEFFFFull));
#else
	lpSystemInfo->lpMaximumApplicationAddress = toGuestPtr(reinterpret_cast<void *>(0x7FFEFFFF));
#endif

	unsigned int cpuCount = 1;
	long reported = sysconf(_SC_NPROCESSORS_ONLN);
	if (reported > 0) {
		cpuCount = static_cast<unsigned int>(reported);
	}
	lpSystemInfo->dwNumberOfProcessors = cpuCount;
	lpSystemInfo->dwActiveProcessorMask = computeSystemProcessorMask(cpuCount);

	lpSystemInfo->dwAllocationGranularity = 0x10000;
}

void WINAPI GetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetNativeSystemInfo -> ");
	GetSystemInfo(lpSystemInfo);
}

void WINAPI GetSystemTime(LPSYSTEMTIME lpSystemTime) {
	HOST_CONTEXT_GUARD();
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

void WINAPI GetLocalTime(LPSYSTEMTIME lpSystemTime) {
	HOST_CONTEXT_GUARD();
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

void WINAPI GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime) {
	HOST_CONTEXT_GUARD();
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

DWORD WINAPI GetTickCount() {
	HOST_CONTEXT_GUARD();
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

DWORD WINAPI GetVersion() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetVersion()\n");
	return kMajorVersion | (kMinorVersion << 8) | (5 << 16) | (kBuildNumber << 24);
}

ULONGLONG WINAPI VerSetConditionMask(ULONGLONG ConditionMask, DWORD TypeMask, BYTE Condition) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("VerSetConditionMask(%llu, 0x%x, %u)\n", ConditionMask, TypeMask, Condition);
	Condition &= 0x07;
	if (TypeMask == 0 || Condition == 0) {
		return ConditionMask;
	}
	// Only the highest-numbered type in the mask is recorded, per the documented behaviour.
	if (TypeMask & VER_PRODUCT_TYPE) {
		ConditionMask |= static_cast<ULONGLONG>(Condition) << (7 * 3);
	} else if (TypeMask & VER_SUITENAME) {
		ConditionMask |= static_cast<ULONGLONG>(Condition) << (6 * 3);
	} else if (TypeMask & VER_SERVICEPACKMAJOR) {
		ConditionMask |= static_cast<ULONGLONG>(Condition) << (5 * 3);
	} else if (TypeMask & VER_SERVICEPACKMINOR) {
		ConditionMask |= static_cast<ULONGLONG>(Condition) << (4 * 3);
	} else if (TypeMask & VER_PLATFORMID) {
		ConditionMask |= static_cast<ULONGLONG>(Condition) << (3 * 3);
	} else if (TypeMask & VER_BUILDNUMBER) {
		ConditionMask |= static_cast<ULONGLONG>(Condition) << (2 * 3);
	} else if (TypeMask & VER_MAJORVERSION) {
		ConditionMask |= static_cast<ULONGLONG>(Condition) << (1 * 3);
	} else if (TypeMask & VER_MINORVERSION) {
		ConditionMask |= static_cast<ULONGLONG>(Condition) << (0 * 3);
	}
	return ConditionMask;
}

BOOL WINAPI VerifyVersionInfoW(LPOSVERSIONINFOEXW lpVersionInformation, DWORD dwTypeMask, ULONGLONG dwlConditionMask) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("VerifyVersionInfoW(%p, 0x%x, %llu) -> ", lpVersionInformation, dwTypeMask, dwlConditionMask);
	if (!lpVersionInformation || dwTypeMask == 0 || dwlConditionMask == 0) {
		setLastError(ERROR_INVALID_PARAMETER);
		DEBUG_LOG("ERROR_INVALID_PARAMETER\n");
		return FALSE;
	}

	OSVERSIONINFOEXW ours{};
	ours.dwOSVersionInfoSize = sizeof(ours);
	if (ntdll::RtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&ours)) != STATUS_SUCCESS) {
		setLastError(ERROR_INVALID_PARAMETER);
		DEBUG_LOG("ERROR_INVALID_PARAMETER\n");
		return FALSE;
	}

	bool matches = true;
	if (dwTypeMask & VER_PRODUCT_TYPE) {
		matches = matches && compareValues(ours.wProductType, lpVersionInformation->wProductType,
										   conditionFor(dwlConditionMask, 7));
	}
	if (dwTypeMask & VER_SUITENAME) {
		matches = matches &&
				  compareMask(ours.wSuiteMask, lpVersionInformation->wSuiteMask, conditionFor(dwlConditionMask, 6));
	}
	if (dwTypeMask & VER_PLATFORMID) {
		matches = matches && compareValues(ours.dwPlatformId, lpVersionInformation->dwPlatformId,
										   conditionFor(dwlConditionMask, 3));
	}
	if (dwTypeMask & VER_BUILDNUMBER) {
		matches = matches && compareValues(ours.dwBuildNumber, lpVersionInformation->dwBuildNumber,
										   conditionFor(dwlConditionMask, 2));
	}

	// One version number: the first component that differs decides.
	constexpr DWORD kVersionTypes = VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR;
	if (matches && (dwTypeMask & kVersionTypes)) {
		BYTE condition = 0;
		if (dwTypeMask & VER_MAJORVERSION) {
			condition = conditionFor(dwlConditionMask, 1);
		} else if (dwTypeMask & VER_MINORVERSION) {
			condition = conditionFor(dwlConditionMask, 0);
		} else if (dwTypeMask & VER_SERVICEPACKMAJOR) {
			condition = conditionFor(dwlConditionMask, 5);
		} else {
			condition = conditionFor(dwlConditionMask, 4);
		}

		const DWORD oursValues[4] = {ours.dwMajorVersion, ours.dwMinorVersion, ours.wServicePackMajor,
									 ours.wServicePackMinor};
		const DWORD wantedValues[4] = {lpVersionInformation->dwMajorVersion, lpVersionInformation->dwMinorVersion,
									   lpVersionInformation->wServicePackMajor,
									   lpVersionInformation->wServicePackMinor};
		const DWORD types[4] = {VER_MAJORVERSION, VER_MINORVERSION, VER_SERVICEPACKMAJOR, VER_SERVICEPACKMINOR};

		matches = condition == VER_EQUAL;
		for (int i = 0; i < 4; ++i) {
			if ((dwTypeMask & types[i]) == 0) {
				continue;
			}
			if (oursValues[i] != wantedValues[i]) {
				matches = compareValues(oursValues[i], wantedValues[i], condition);
				break;
			}
			matches = condition != VER_GREATER && condition != VER_LESS;
		}
	}

	if (!matches) {
		setLastError(ERROR_OLD_WIN_VERSION);
		DEBUG_LOG("FALSE\n");
		return FALSE;
	}
	DEBUG_LOG("TRUE\n");
	return TRUE;
}

BOOL WINAPI GetVersionExA(LPOSVERSIONINFOA lpVersionInformation) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetVersionExA(%p)\n", lpVersionInformation);
	if (!lpVersionInformation) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	DWORD size = lpVersionInformation->dwOSVersionInfoSize;
	if (size < sizeof(OSVERSIONINFOA)) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	DWORD requestSize = (size >= sizeof(OSVERSIONINFOEXA)) ? sizeof(OSVERSIONINFOEXW) : sizeof(OSVERSIONINFOW);
	OSVERSIONINFOEXW wideInfo{};
	wideInfo.dwOSVersionInfoSize = requestSize;
	NTSTATUS status = ntdll::RtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&wideInfo));
	if (status != STATUS_SUCCESS) {
		setLastError(wibo::winErrorFromNtStatus(status));
		return FALSE;
	}

	std::memset(lpVersionInformation, 0, size);
	lpVersionInformation->dwOSVersionInfoSize = size;
	lpVersionInformation->dwMajorVersion = wideInfo.dwMajorVersion;
	lpVersionInformation->dwMinorVersion = wideInfo.dwMinorVersion;
	lpVersionInformation->dwBuildNumber = wideInfo.dwBuildNumber;
	lpVersionInformation->dwPlatformId = wideInfo.dwPlatformId;

	if (size >= sizeof(OSVERSIONINFOEXA)) {
		auto extended = reinterpret_cast<OSVERSIONINFOEXA *>(lpVersionInformation);
		extended->wServicePackMajor = wideInfo.wServicePackMajor;
		extended->wServicePackMinor = wideInfo.wServicePackMinor;
		extended->wSuiteMask = wideInfo.wSuiteMask;
		extended->wProductType = wideInfo.wProductType;
		extended->wReserved = wideInfo.wReserved;
	}

	return TRUE;
}

BOOL WINAPI GetVersionExW(LPOSVERSIONINFOW lpVersionInformation) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetVersionExW(%p)\n", lpVersionInformation);
	if (!lpVersionInformation) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	DWORD size = lpVersionInformation->dwOSVersionInfoSize;
	if (size < sizeof(OSVERSIONINFOW)) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	NTSTATUS status = ntdll::RtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(lpVersionInformation));
	if (status != STATUS_SUCCESS) {
		setLastError(wibo::winErrorFromNtStatus(status));
		return FALSE;
	}

	lpVersionInformation->dwOSVersionInfoSize = size;
	return TRUE;
}

} // namespace kernel32
