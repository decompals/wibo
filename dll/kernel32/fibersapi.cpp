#include "fibersapi.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "internal.h"

namespace {

constexpr DWORD kMaxFlsValues = 0x100;
bool g_flsValuesUsed[kMaxFlsValues] = {false};
LPVOID g_flsValues[kMaxFlsValues] = {nullptr};

} // namespace

namespace kernel32 {

DWORD WIN_FUNC FlsAlloc(PFLS_CALLBACK_FUNCTION lpCallback) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FlsAlloc(%p)", lpCallback);
	// If the function succeeds, the return value is an FLS index initialized to zero.
	for (DWORD i = 0; i < kMaxFlsValues; i++) {
		if (g_flsValuesUsed[i] == false) {
			g_flsValuesUsed[i] = true;
			g_flsValues[i] = nullptr;
			DEBUG_LOG(" -> %d\n", i);
			return i;
		}
	}
	DEBUG_LOG(" -> -1\n");
	setLastError(FLS_OUT_OF_INDEXES);
	return FLS_OUT_OF_INDEXES;
}

BOOL WIN_FUNC FlsFree(DWORD dwFlsIndex) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FlsFree(%u)\n", dwFlsIndex);
	if (dwFlsIndex < kMaxFlsValues && g_flsValuesUsed[dwFlsIndex]) {
		g_flsValuesUsed[dwFlsIndex] = false;
		return TRUE;
	} else {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
}

PVOID WIN_FUNC FlsGetValue(DWORD dwFlsIndex) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("FlsGetValue(%u)\n", dwFlsIndex);
	PVOID result = nullptr;
	if (dwFlsIndex < kMaxFlsValues && g_flsValuesUsed[dwFlsIndex]) {
		result = g_flsValues[dwFlsIndex];
		// See https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsgetvalue
		setLastError(ERROR_SUCCESS);
	} else {
		setLastError(ERROR_INVALID_PARAMETER);
	}
	// DEBUG_LOG(" -> %p\n", result);
	return result;
}

BOOL WIN_FUNC FlsSetValue(DWORD dwFlsIndex, PVOID lpFlsData) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("FlsSetValue(%u, %p)\n", dwFlsIndex, lpFlsData);
	if (dwFlsIndex < kMaxFlsValues && g_flsValuesUsed[dwFlsIndex]) {
		g_flsValues[dwFlsIndex] = lpFlsData;
		return TRUE;
	} else {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
}

} // namespace kernel32
