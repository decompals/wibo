#include "processthreadsapi.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "handles.h"
#include "internal.h"
#include "kernel32/internal.h"
#include "processes.h"

namespace advapi32 {

BOOL WIN_FUNC OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("OpenProcessToken(%p, %u, %p)\n", ProcessHandle, DesiredAccess, TokenHandle);
	if (!TokenHandle) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	Pin<ProcessObject> obj;
	if (kernel32::isPseudoCurrentProcessHandle(ProcessHandle)) {
		obj = make_pin<ProcessObject>(getpid(), -1);
	} else {
		obj = wibo::handles().getAs<ProcessObject>(ProcessHandle);
	}
	if (!obj) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	auto token = make_pin<TokenObject>(std::move(obj), DesiredAccess);
	*TokenHandle = wibo::handles().alloc(std::move(token), 0, 0);
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

} // namespace advapi32
