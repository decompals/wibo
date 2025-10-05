#include "handleapi.h"

#include "context.h"
#include "errors.h"
#include "handles.h"
#include "internal.h"

#include <pthread.h>
#include <unistd.h>

namespace kernel32 {

BOOL WIN_FUNC DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle,
							  LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("DuplicateHandle(%p, %p, %p, %p, %x, %d, %x)\n", hSourceProcessHandle, hSourceHandle,
			  hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);
	(void)dwDesiredAccess;
	(void)dwOptions;
	if (!lpTargetHandle) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	auto validateProcessHandle = [&](HANDLE handle) -> bool {
		if (reinterpret_cast<uintptr_t>(handle) == kPseudoCurrentProcessHandleValue) {
			return true;
		}
		auto proc = wibo::handles().getAs<ProcessObject>(handle);
		return proc && proc->pid == getpid();
	};

	if (!validateProcessHandle(hSourceProcessHandle) || !validateProcessHandle(hTargetProcessHandle)) {
		DEBUG_LOG("DuplicateHandle: unsupported process handle combination (source=%p target=%p)\n",
				  hSourceProcessHandle, hTargetProcessHandle);
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}

	uintptr_t sourceHandleRaw = reinterpret_cast<uintptr_t>(hSourceHandle);
	if (sourceHandleRaw == kPseudoCurrentProcessHandleValue) {
		auto po = make_pin<ProcessObject>(getpid(), -1);
		auto handle = wibo::handles().alloc(std::move(po), 0, 0);
		DEBUG_LOG("DuplicateHandle: created process handle for current process -> %p\n", handle);
		*lpTargetHandle = handle;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	} else if (sourceHandleRaw == kPseudoCurrentThreadHandleValue) {
		auto th = make_pin<ThreadObject>(pthread_self());
		auto handle = wibo::handles().alloc(std::move(th), 0, 0);
		DEBUG_LOG("DuplicateHandle: created thread handle for current thread -> %p\n", handle);
		*lpTargetHandle = handle;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	if (!wibo::handles().duplicateTo(hSourceHandle, wibo::handles(), *lpTargetHandle, dwDesiredAccess, bInheritHandle,
									 dwOptions)) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC CloseHandle(HANDLE hObject) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CloseHandle(%p)\n", hObject);
	if (!wibo::handles().release(hObject)) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

} // namespace kernel32
