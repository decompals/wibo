#include "winmm.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "modules.h"

#include <ctime>

namespace winmm {

DWORD WINAPI timeGetTime() {
	HOST_CONTEXT_GUARD();
	struct timespec ts{};
	clock_gettime(CLOCK_MONOTONIC, &ts);
	uint64_t milliseconds = static_cast<uint64_t>(ts.tv_sec) * 1000ULL + static_cast<uint64_t>(ts.tv_nsec) / 1000000ULL;
	DWORD value = static_cast<DWORD>(milliseconds & 0xFFFFFFFFULL);
	VERBOSE_LOG("timeGetTime() -> %u\n", value);
	return value;
}

MMRESULT WINAPI timeGetDevCaps(LPTIMECAPS ptc, UINT cbtc) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("timeGetDevCaps(%p, %u)\n", ptc, cbtc);
	if (!ptc || cbtc < sizeof(TIMECAPS)) {
		return 11; // TIMERR_NOCANDO
	}
	ptc->wPeriodMin = 1;
	ptc->wPeriodMax = 1000;
	return 0; // TIMERR_NOERROR
}

} // namespace winmm

#include "winmm_trampolines.h"

extern const wibo::ModuleStub lib_winmm = {
	(const char *[]){
		"winmm",
		"winmm.dll",
		nullptr,
	},
	winmmThunkByName,
	nullptr,
	{},
};
