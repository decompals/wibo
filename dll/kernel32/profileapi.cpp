#include "profileapi.h"

#include "common.h"
#include "context.h"
#include "errors.h"

namespace kernel32 {

BOOL WIN_FUNC QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("STUB: QueryPerformanceCounter(%p)\n", lpPerformanceCount);
	if (!lpPerformanceCount) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	*lpPerformanceCount = 0;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("STUB: QueryPerformanceFrequency(%p)\n", lpFrequency);
	if (!lpFrequency) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	*lpFrequency = 1;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

} // namespace kernel32
