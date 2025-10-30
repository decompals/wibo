#include "wow64apiset.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "handles.h"
#include "internal.h"

namespace kernel32 {

BOOL WINAPI Wow64DisableWow64FsRedirection(PVOID *OldValue) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: Wow64DisableWow64FsRedirection(%p)\n", OldValue);
	if (OldValue) {
		*OldValue = nullptr;
	}
	return TRUE;
}

BOOL WINAPI Wow64RevertWow64FsRedirection(PVOID OldValue) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: Wow64RevertWow64FsRedirection(%p)\n", OldValue);
	(void)OldValue;
	return TRUE;
}

BOOL WINAPI IsWow64Process(HANDLE hProcess, PBOOL Wow64Process) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("IsWow64Process(%p, %p)\n", hProcess, Wow64Process);
	if (!Wow64Process) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if (!isPseudoCurrentProcessHandle(hProcess)) {
		if (!hProcess) {
			setLastError(ERROR_INVALID_HANDLE);
			return FALSE;
		}
		auto obj = wibo::handles().getAs<ProcessObject>(hProcess);
		if (!obj) {
			setLastError(ERROR_INVALID_HANDLE);
			return FALSE;
		}
	}

	*Wow64Process = FALSE;
	return TRUE;
}

} // namespace kernel32
