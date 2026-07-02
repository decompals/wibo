#include "fibersapi.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "internal.h"

#include <array>
#include <mutex>

namespace {

constexpr DWORD kMaxFlsValues = 0x100;

struct FlsSlot {
	DWORD generation = 0;
	LPVOID value = nullptr;
};

std::mutex g_flsMutex;
bool g_flsValuesUsed[kMaxFlsValues] = {false};
DWORD g_flsGenerations[kMaxFlsValues] = {0};
thread_local std::array<FlsSlot, kMaxFlsValues> t_flsValues;

void resetThreadFlsSlot(DWORD index) {
	FlsSlot &slot = t_flsValues[index];
	if (slot.generation != g_flsGenerations[index]) {
		slot.generation = g_flsGenerations[index];
		slot.value = nullptr;
	}
}

} // namespace

namespace kernel32 {

DWORD WINAPI FlsAlloc(PFLS_CALLBACK_FUNCTION lpCallback) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FlsAlloc(%p)", lpCallback);
	// If the function succeeds, the return value is an FLS index initialized to zero.
	std::lock_guard lk(g_flsMutex);
	for (DWORD i = 0; i < kMaxFlsValues; i++) {
		if (g_flsValuesUsed[i] == false) {
			g_flsValuesUsed[i] = true;
			g_flsGenerations[i]++;
			resetThreadFlsSlot(i);
			DEBUG_LOG(" -> %d\n", i);
			return i;
		}
	}
	DEBUG_LOG(" -> -1\n");
	setLastError(FLS_OUT_OF_INDEXES);
	return FLS_OUT_OF_INDEXES;
}

BOOL WINAPI FlsFree(DWORD dwFlsIndex) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FlsFree(%u)\n", dwFlsIndex);
	std::lock_guard lk(g_flsMutex);
	if (dwFlsIndex < kMaxFlsValues && g_flsValuesUsed[dwFlsIndex]) {
		g_flsValuesUsed[dwFlsIndex] = false;
		return TRUE;
	} else {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
}

PVOID WINAPI FlsGetValue(DWORD dwFlsIndex) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("FlsGetValue(%u)\n", dwFlsIndex);
	PVOID result = nullptr;
	std::lock_guard lk(g_flsMutex);
	if (dwFlsIndex < kMaxFlsValues && g_flsValuesUsed[dwFlsIndex]) {
		resetThreadFlsSlot(dwFlsIndex);
		result = t_flsValues[dwFlsIndex].value;
		// See https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsgetvalue
		setLastError(ERROR_SUCCESS);
	} else {
		setLastError(ERROR_INVALID_PARAMETER);
	}
	// DEBUG_LOG(" -> %p\n", result);
	return result;
}

BOOL WINAPI FlsSetValue(DWORD dwFlsIndex, PVOID lpFlsData) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("FlsSetValue(%u, %p)\n", dwFlsIndex, lpFlsData);
	std::lock_guard lk(g_flsMutex);
	if (dwFlsIndex < kMaxFlsValues && g_flsValuesUsed[dwFlsIndex]) {
		resetThreadFlsSlot(dwFlsIndex);
		t_flsValues[dwFlsIndex].value = lpFlsData;
		return TRUE;
	} else {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
}

} // namespace kernel32
