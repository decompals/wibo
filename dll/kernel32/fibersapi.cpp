#include "common.h"
#include "errors.h"
#include "kernel32.h"

namespace kernel32 {

constexpr size_t MAX_FLS_VALUES = 0x100;
static bool flsValuesUsed[MAX_FLS_VALUES] = {false};
static void *flsValues[MAX_FLS_VALUES];

DWORD WIN_FUNC FlsAlloc(PFLS_CALLBACK_FUNCTION lpCallback) {
	DEBUG_LOG("FlsAlloc(%p)", lpCallback);
	// If the function succeeds, the return value is an FLS index initialized to zero.
	for (size_t i = 0; i < MAX_FLS_VALUES; i++) {
		if (flsValuesUsed[i] == false) {
			flsValuesUsed[i] = true;
			flsValues[i] = nullptr;
			DEBUG_LOG(" -> %d\n", i);
			return i;
		}
	}
	DEBUG_LOG(" -> -1\n");
	wibo::lastError = 1;
	return FLS_OUT_OF_INDEXES;
}

BOOL WIN_FUNC FlsFree(DWORD dwFlsIndex) {
	DEBUG_LOG("FlsFree(%u)\n", dwFlsIndex);
	if (dwFlsIndex >= 0 && dwFlsIndex < MAX_FLS_VALUES && flsValuesUsed[dwFlsIndex]) {
		flsValuesUsed[dwFlsIndex] = false;
		return TRUE;
	} else {
		wibo::lastError = 1;
		return FALSE;
	}
}

PVOID WIN_FUNC FlsGetValue(DWORD dwFlsIndex) {
	VERBOSE_LOG("FlsGetValue(%u)\n", dwFlsIndex);
	PVOID result = nullptr;
	if (dwFlsIndex >= 0 && dwFlsIndex < MAX_FLS_VALUES && flsValuesUsed[dwFlsIndex]) {
		result = flsValues[dwFlsIndex];
		// See https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsgetvalue
		wibo::lastError = ERROR_SUCCESS;
	} else {
		wibo::lastError = 1;
	}
	// DEBUG_LOG(" -> %p\n", result);
	return result;
}

BOOL WIN_FUNC FlsSetValue(DWORD dwFlsIndex, PVOID lpFlsData) {
	VERBOSE_LOG("FlsSetValue(%u, %p)\n", dwFlsIndex, lpFlsData);
	if (dwFlsIndex >= 0 && dwFlsIndex < MAX_FLS_VALUES && flsValuesUsed[dwFlsIndex]) {
		flsValues[dwFlsIndex] = lpFlsData;
		return TRUE;
	} else {
		wibo::lastError = 1;
		return FALSE;
	}
}

} // namespace kernel32
