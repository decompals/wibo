#include "common.h"
#include "kernel32.h"

#include <cstring>

namespace {
constexpr WORD PROCESSOR_ARCHITECTURE_INTEL = 0;
constexpr DWORD PROCESSOR_INTEL_PENTIUM = 586;

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

} // namespace kernel32
