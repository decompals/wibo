#include "handleapi.h"

#include "context.h"
#include "errors.h"
#include "files.h"
#include "handles.h"
#include "internal.h"

#include <cstdio>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

namespace kernel32 {

BOOL WINAPI DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle,
							LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("DuplicateHandle(%p, %p, %p, %p, %x, %d, %x)\n", hSourceProcessHandle, hSourceHandle,
			  hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);
	(void)dwDesiredAccess;
	(void)dwOptions;
	if (!lpTargetHandle) {
		DEBUG_LOG("-> ERROR_INVALID_PARAMETER\n");
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	auto validateSourceProcessHandle = [&](HANDLE handle) -> bool {
		if (isPseudoCurrentProcessHandle(handle)) {
			return true;
		}
		auto proc = wibo::handles().getAs<ProcessObject>(handle);
		return proc && proc->pid == getpid();
	};
	auto validateTargetProcessHandle = [&](HANDLE handle) -> bool {
		if (isPseudoCurrentProcessHandle(handle)) {
			return true;
		}
		return static_cast<bool>(wibo::handles().getAs<ProcessObject>(handle));
	};

	if (!validateSourceProcessHandle(hSourceProcessHandle) || !validateTargetProcessHandle(hTargetProcessHandle)) {
		DEBUG_LOG("DuplicateHandle: unsupported process handle combination (source=%p target=%p)\n",
				  hSourceProcessHandle, hTargetProcessHandle);
		setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}

	auto &handles = wibo::handles();
	if (isPseudoCurrentProcessHandle(hSourceHandle)) {
		auto po = make_pin<ProcessObject>(getpid(), -1, false);
		auto handle = handles.alloc(std::move(po), 0, 0);
		DEBUG_LOG("DuplicateHandle: created process handle for current process -> %p\n", handle);
		*lpTargetHandle = handle;
		return TRUE;
	} else if (isPseudoCurrentThreadHandle(hSourceHandle)) {
		auto th = make_pin<ThreadObject>(pthread_self());
		auto handle = handles.alloc(std::move(th), 0, 0);
		DEBUG_LOG("DuplicateHandle: created thread handle for current thread -> %p\n", handle);
		*lpTargetHandle = handle;
		return TRUE;
	}

	if (!handles.get(hSourceHandle)) {
		files::materializeInheritedFileHandle(hSourceHandle);
	}

	auto sourceFile = handles.getAs<FileObject>(hSourceHandle);
	auto targetProcess = wibo::handles().getAs<ProcessObject>(hTargetProcessHandle);
	if (!sourceFile && targetProcess && targetProcess->pid != getpid() &&
		files::hasInheritedFileHandleRecord(hSourceHandle)) {
		*lpTargetHandle = hSourceHandle;
		DEBUG_LOG("DuplicateHandle: treating recorded remote file handle %p as already duplicated\n", hSourceHandle);
		return TRUE;
	}
	if (sourceFile && targetProcess && targetProcess->pid != getpid()) {
		HandleMeta meta{};
		sourceFile = handles.getAs<FileObject>(hSourceHandle, &meta);
		std::string registryPath = files::inheritedFileRegistryPath(targetProcess->pid).string();
		FILE *f = fopen(registryPath.c_str(), "a");
		if (!f) {
			setLastError(ERROR_ACCESS_DENIED);
			return FALSE;
		}
		fprintf(f, "%x:%lld:%x:%x:%x:%x\n", static_cast<unsigned>(hSourceHandle), static_cast<long long>(getpid()),
				sourceFile->fd, meta.grantedAccess, meta.flags, sourceFile->appendOnly ? 1 : 0);
		fclose(f);
		*lpTargetHandle = hSourceHandle;
		DEBUG_LOG("DuplicateHandle: registered remote file handle %p for pid %d\n", hSourceHandle, targetProcess->pid);
		if ((dwOptions & DUPLICATE_CLOSE_SOURCE) != 0) {
			handles.release(hSourceHandle);
		}
		return TRUE;
	}

	if (!isPseudoCurrentProcessHandle(hTargetProcessHandle)) {
		DEBUG_LOG("DuplicateHandle: duplicating %p for remote process %p using local handle table\n", hSourceHandle,
				  hTargetProcessHandle);
	}
	if (!handles.duplicateTo(hSourceHandle, handles, *lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions)) {
		DEBUG_LOG("-> ERROR_INVALID_HANDLE\n");
		setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	DEBUG_LOG("-> %p\n", *lpTargetHandle);
	return TRUE;
}

BOOL WINAPI CloseHandle(HANDLE hObject) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CloseHandle(%p)\n", hObject);
	if (!wibo::handles().release(hObject)) {
		setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	return TRUE;
}

BOOL WINAPI SetHandleInformation(HANDLE hObject, DWORD dwMask, DWORD dwFlags) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetHandleInformation(%p, 0x%x, 0x%x)\n", hObject, dwMask, dwFlags);
	if (!wibo::handles().setInformation(hObject, dwMask, dwFlags)) {
		setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	return TRUE;
}

} // namespace kernel32
