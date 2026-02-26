#include "profileapi.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "internal.h"

#include <ctime>

namespace kernel32 {

BOOL WINAPI QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("QueryPerformanceCounter(%p)\n", lpPerformanceCount);
	if (!lpPerformanceCount) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	lpPerformanceCount->QuadPart = static_cast<LONGLONG>(ts.tv_sec) * 1000000000LL + ts.tv_nsec;
	return TRUE;
}

BOOL WINAPI QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("QueryPerformanceFrequency(%p)\n", lpFrequency);
	if (!lpFrequency) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	lpFrequency->QuadPart = 1000000000LL;
	return TRUE;
}
} // namespace kernel32
