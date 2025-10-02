#include "wow64apiset.h"
#include "common.h"
#include "errors.h"
#include "handles.h"

namespace kernel32 {

BOOL WIN_FUNC Wow64DisableWow64FsRedirection(PVOID *OldValue) {
	DEBUG_LOG("STUB: Wow64DisableWow64FsRedirection(%p)\n", OldValue);
	if (OldValue) {
		*OldValue = nullptr;
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC Wow64RevertWow64FsRedirection(PVOID OldValue) {
	DEBUG_LOG("STUB: Wow64RevertWow64FsRedirection(%p)\n", OldValue);
	(void)OldValue;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC IsWow64Process(HANDLE hProcess, PBOOL Wow64Process) {
	DEBUG_LOG("IsWow64Process(%p, %p)\n", hProcess, Wow64Process);
	if (!Wow64Process) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	uintptr_t rawHandle = reinterpret_cast<uintptr_t>(hProcess);
	bool isPseudoHandle = rawHandle == static_cast<uintptr_t>(-1);
	if (!isPseudoHandle) {
		if (!hProcess) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return FALSE;
		}
		auto data = handles::dataFromHandle(hProcess, false);
		if (data.type != handles::TYPE_PROCESS || data.ptr == nullptr) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return FALSE;
		}
	}

	*Wow64Process = FALSE;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

} // namespace kernel32
