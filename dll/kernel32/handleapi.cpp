#include "handleapi.h"

#include "dll/advapi32/internal.h"
#include "errors.h"
#include "files.h"
#include "handles.h"
#include "internal.h"
#include "processes.h"

#include <pthread.h>
#include <unistd.h>

namespace kernel32 {

BOOL WIN_FUNC DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle,
							  LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions) {
	DEBUG_LOG("DuplicateHandle(%p, %p, %p, %p, %x, %d, %x)\n", hSourceProcessHandle, hSourceHandle,
			  hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);
	(void)dwDesiredAccess;
	(void)bInheritHandle;
	(void)dwOptions;
	if (!lpTargetHandle) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	auto validateProcessHandle = [&](HANDLE handle) -> bool {
		uintptr_t raw = reinterpret_cast<uintptr_t>(handle);
		if (raw == static_cast<uintptr_t>(-1)) {
			return true;
		}
		auto data = handles::dataFromHandle(handle, false);
		if (data.type != handles::TYPE_PROCESS || data.ptr == nullptr) {
			return false;
		}
		auto *proc = reinterpret_cast<processes::Process *>(data.ptr);
		return proc && proc->pid == getpid();
	};

	if (!validateProcessHandle(hSourceProcessHandle) || !validateProcessHandle(hTargetProcessHandle)) {
		DEBUG_LOG("DuplicateHandle: unsupported process handle combination (source=%p target=%p)\n",
				  hSourceProcessHandle, hTargetProcessHandle);
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}

	auto file = files::fileHandleFromHandle(hSourceHandle);
	if (file && (file->fp == stdin || file->fp == stdout || file->fp == stderr)) {
		HANDLE handle = files::duplicateFileHandle(file, false);
		DEBUG_LOG("DuplicateHandle: duplicated std handle -> %p\n", handle);
		*lpTargetHandle = handle;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	uintptr_t sourceHandleRaw = reinterpret_cast<uintptr_t>(hSourceHandle);
	if (sourceHandleRaw == static_cast<uintptr_t>(-1)) {
		HANDLE handle = processes::allocProcessHandle(getpid());
		processes::Process *proc = processes::processFromHandle(handle, false);
		if (proc) {
			proc->exitCode = STILL_ACTIVE;
			proc->forcedExitCode = STILL_ACTIVE;
			proc->terminationRequested = false;
		}
		DEBUG_LOG("DuplicateHandle: created process handle for current process -> %p\n", handle);
		*lpTargetHandle = handle;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	if (sourceHandleRaw == kPseudoCurrentThreadHandleValue) {
		ThreadObject *obj = ensureCurrentThreadObject();
		if (obj) {
			retainThreadObject(obj);
			HANDLE handle = handles::allocDataHandle({handles::TYPE_THREAD, obj, 0});
			DEBUG_LOG("DuplicateHandle: duplicated pseudo current thread -> %p\n", handle);
			*lpTargetHandle = handle;
			wibo::lastError = ERROR_SUCCESS;
			return TRUE;
		}
		ThreadObject *syntheticObj = new ThreadObject();
		syntheticObj->thread = pthread_self();
		syntheticObj->finished = false;
		syntheticObj->joined = false;
		syntheticObj->detached = true;
		syntheticObj->synthetic = true;
		syntheticObj->exitCode = 0;
		syntheticObj->refCount = 1;
		syntheticObj->suspendCount = 0;
		pthread_mutex_init(&syntheticObj->mutex, nullptr);
		pthread_cond_init(&syntheticObj->cond, nullptr);
		HANDLE handle = handles::allocDataHandle({handles::TYPE_THREAD, syntheticObj, 0});
		DEBUG_LOG("DuplicateHandle: created synthetic thread handle -> %p\n", handle);
		*lpTargetHandle = handle;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	handles::Data data = handles::dataFromHandle(hSourceHandle, false);
	if (data.type == handles::TYPE_PROCESS && data.ptr) {
		auto *original = reinterpret_cast<processes::Process *>(data.ptr);
		HANDLE handle = processes::allocProcessHandle(original->pid);
		auto *copy = processes::processFromHandle(handle, false);
		if (copy) {
			*copy = *original;
		}
		DEBUG_LOG("DuplicateHandle: duplicated process handle -> %p\n", handle);
		*lpTargetHandle = handle;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	if (data.type == handles::TYPE_THREAD && data.ptr) {
		auto *threadObj = reinterpret_cast<ThreadObject *>(data.ptr);
		if (!retainThreadObject(threadObj)) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return FALSE;
		}
		HANDLE handle = handles::allocDataHandle({handles::TYPE_THREAD, threadObj, 0});
		DEBUG_LOG("DuplicateHandle: duplicated thread handle -> %p\n", handle);
		*lpTargetHandle = handle;
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	DEBUG_LOG("DuplicateHandle: unsupported handle type for %p\n", hSourceHandle);
	wibo::lastError = ERROR_INVALID_HANDLE;
	return FALSE;
}

BOOL WIN_FUNC CloseHandle(HANDLE hObject) {
	DEBUG_LOG("CloseHandle(%p)\n", hObject);
	auto data = handles::dataFromHandle(hObject, true);
	if (data.type == handles::TYPE_UNUSED || data.ptr == nullptr) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	bool success = true;
	if (data.type == handles::TYPE_FILE) {
		auto file = reinterpret_cast<files::FileHandle *>(data.ptr);
		if (file) {
			if (file->closeOnDestroy && file->fp && !(file->fp == stdin || file->fp == stdout || file->fp == stderr)) {
				fclose(file->fp);
			}
			delete file;
		} else {
			success = false;
		}
	} else if (data.type == handles::TYPE_MAPPED) {
		if (!closeFileMappingHandle(data.ptr)) {
			success = false;
		}
	} else if (data.type == handles::TYPE_PROCESS) {
		delete reinterpret_cast<processes::Process *>(data.ptr);
	} else if (data.type == handles::TYPE_TOKEN) {
		delete reinterpret_cast<TokenObject *>(data.ptr);
	} else if (data.type == handles::TYPE_MUTEX) {
		releaseMutexObject(reinterpret_cast<MutexObject *>(data.ptr));
	} else if (data.type == handles::TYPE_EVENT) {
		releaseEventObject(reinterpret_cast<EventObject *>(data.ptr));
	} else if (data.type == handles::TYPE_THREAD) {
		releaseThreadObject(reinterpret_cast<ThreadObject *>(data.ptr));
	} else if (data.type == handles::TYPE_SEMAPHORE) {
		releaseSemaphoreObject(reinterpret_cast<SemaphoreObject *>(data.ptr));
	} else {
		success = false;
	}
	if (!success) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

} // namespace kernel32
