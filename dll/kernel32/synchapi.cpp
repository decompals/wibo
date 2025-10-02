#include "synchapi.h"
#include "common.h"
#include "errors.h"
#include "handles.h"
#include "internal.h"
#include "processes.h"
#include "strutil.h"

#include <cerrno>
#include <cstring>
#include <mutex>
#include <pthread.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace {

std::u16string makeMutexName(LPCWSTR name) {
	if (!name) {
		return {};
	}
	size_t len = wstrlen(reinterpret_cast<const uint16_t *>(name));
	return {reinterpret_cast<const char16_t *>(name), len};
}

void makeWideNameFromAnsi(LPCSTR ansiName, std::vector<uint16_t> &outWide) {
	outWide.clear();
	if (!ansiName) {
		return;
	}
	outWide = stringToWideString(ansiName);
}

} // namespace

namespace kernel32 {

void WIN_FUNC Sleep(DWORD dwMilliseconds) {
	DEBUG_LOG("Sleep(%u)\n", dwMilliseconds);
	usleep(static_cast<useconds_t>(dwMilliseconds) * 1000);
}

namespace {

std::mutex mutexRegistryLock;
std::unordered_map<std::u16string, MutexObject *> namedMutexes;

std::mutex eventRegistryLock;
std::unordered_map<std::u16string, EventObject *> namedEvents;

std::mutex semaphoreRegistryLock;
std::unordered_map<std::u16string, SemaphoreObject *> namedSemaphores;

EventObject *eventObjectFromHandle(HANDLE hEvent) {
	auto data = handles::dataFromHandle(hEvent, false);
	if (data.type != handles::TYPE_EVENT || data.ptr == nullptr) {
		return nullptr;
	}
	return reinterpret_cast<EventObject *>(data.ptr);
}

SemaphoreObject *semaphoreObjectFromHandle(HANDLE hSemaphore) {
	auto data = handles::dataFromHandle(hSemaphore, false);
	if (data.type != handles::TYPE_SEMAPHORE || data.ptr == nullptr) {
		return nullptr;
	}
	return reinterpret_cast<SemaphoreObject *>(data.ptr);
}

MutexObject *mutexObjectFromHandle(HANDLE hMutex) {
	auto data = handles::dataFromHandle(hMutex, false);
	if (data.type != handles::TYPE_MUTEX || data.ptr == nullptr) {
		return nullptr;
	}
	return reinterpret_cast<MutexObject *>(data.ptr);
}

bool setEventSignaledState(HANDLE hEvent, bool signaled) {
	EventObject *obj = eventObjectFromHandle(hEvent);
	if (!obj) {
		return false;
	}
	pthread_mutex_lock(&obj->mutex);
	obj->signaled = signaled;
	if (signaled) {
		if (obj->manualReset) {
			pthread_cond_broadcast(&obj->cond);
		} else {
			pthread_cond_signal(&obj->cond);
		}
	}
	pthread_mutex_unlock(&obj->mutex);
	return true;
}

} // namespace

void releaseMutexObject(MutexObject *obj) {
	if (!obj) {
		return;
	}
	std::lock_guard<std::mutex> lock(mutexRegistryLock);
	obj->refCount--;
	if (obj->refCount == 0) {
		if (!obj->name.empty()) {
			namedMutexes.erase(obj->name);
		}
		pthread_mutex_destroy(&obj->mutex);
		delete obj;
	}
}

void releaseEventObject(EventObject *obj) {
	if (!obj) {
		return;
	}
	std::lock_guard<std::mutex> lock(eventRegistryLock);
	obj->refCount--;
	if (obj->refCount == 0) {
		if (!obj->name.empty()) {
			namedEvents.erase(obj->name);
		}
		pthread_cond_destroy(&obj->cond);
		pthread_mutex_destroy(&obj->mutex);
		delete obj;
	}
}

void releaseSemaphoreObject(SemaphoreObject *obj) {
	if (!obj) {
		return;
	}
	std::lock_guard<std::mutex> lock(semaphoreRegistryLock);
	obj->refCount--;
	if (obj->refCount == 0) {
		if (!obj->name.empty()) {
			namedSemaphores.erase(obj->name);
		}
		pthread_cond_destroy(&obj->cond);
		pthread_mutex_destroy(&obj->mutex);
		delete obj;
	}
}

HANDLE WIN_FUNC CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName) {
	std::string nameLog;
	if (lpName) {
		nameLog = wideStringToString(reinterpret_cast<const uint16_t *>(lpName));
	} else {
		nameLog = "<unnamed>";
	}
	DEBUG_LOG("CreateMutexW(%p, %d, %s)\n", lpMutexAttributes, bInitialOwner, nameLog.c_str());
	(void)lpMutexAttributes;

	std::u16string name = makeMutexName(lpName);
	MutexObject *obj = nullptr;
	bool alreadyExists = false;
	{
		std::lock_guard<std::mutex> lock(mutexRegistryLock);
		if (!name.empty()) {
			auto it = namedMutexes.find(name);
			if (it != namedMutexes.end()) {
				obj = it->second;
				obj->refCount++;
				alreadyExists = true;
			}
		}
		if (!obj) {
			obj = new MutexObject();
			pthread_mutexattr_t attr;
			pthread_mutexattr_init(&attr);
			pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
			pthread_mutex_init(&obj->mutex, &attr);
			pthread_mutexattr_destroy(&attr);
			obj->name = name;
			if (!name.empty()) {
				namedMutexes[name] = obj;
			}
		}
	}

	if (!alreadyExists && bInitialOwner) {
		pthread_mutex_lock(&obj->mutex);
		obj->owner = pthread_self();
		obj->ownerValid = true;
		obj->recursionCount = 1;
	}

	HANDLE handle = handles::allocDataHandle({handles::TYPE_MUTEX, obj, 0});
	wibo::lastError = alreadyExists ? ERROR_ALREADY_EXISTS : ERROR_SUCCESS;
	return handle;
}

HANDLE WIN_FUNC CreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName) {
	DEBUG_LOG("CreateMutexA -> ");
	std::vector<uint16_t> wideName;
	makeWideNameFromAnsi(lpName, wideName);
	return CreateMutexW(lpMutexAttributes, bInitialOwner,
						lpName ? reinterpret_cast<LPCWSTR>(wideName.data()) : nullptr);
}

BOOL WIN_FUNC ReleaseMutex(HANDLE hMutex) {
	DEBUG_LOG("ReleaseMutex(%p)\n", hMutex);
	MutexObject *obj = mutexObjectFromHandle(hMutex);
	if (!obj) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	pthread_t self = pthread_self();
	pthread_mutex_lock(&obj->mutex);
	if (!obj->ownerValid || !pthread_equal(obj->owner, self) || obj->recursionCount == 0) {
		pthread_mutex_unlock(&obj->mutex);
		wibo::lastError = ERROR_NOT_OWNER;
		return FALSE;
	}
	obj->recursionCount--;
	if (obj->recursionCount == 0) {
		obj->ownerValid = false;
	}
	pthread_mutex_unlock(&obj->mutex);
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

HANDLE WIN_FUNC CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState,
							 LPCWSTR lpName) {
	std::string nameLog;
	if (lpName) {
		nameLog = wideStringToString(reinterpret_cast<const uint16_t *>(lpName));
	} else {
		nameLog = "<unnamed>";
	}
	DEBUG_LOG("CreateEventW(name=%s, manualReset=%d, initialState=%d)\n", nameLog.c_str(), bManualReset, bInitialState);
	(void)lpEventAttributes;

	std::u16string name = makeMutexName(lpName);
	EventObject *obj = nullptr;
	bool alreadyExists = false;
	{
		std::lock_guard<std::mutex> lock(eventRegistryLock);
		if (!name.empty()) {
			auto it = namedEvents.find(name);
			if (it != namedEvents.end()) {
				obj = it->second;
				obj->refCount++;
				alreadyExists = true;
			}
		}
		if (!obj) {
			obj = new EventObject();
			pthread_mutex_init(&obj->mutex, nullptr);
			pthread_cond_init(&obj->cond, nullptr);
			obj->manualReset = bManualReset;
			obj->signaled = bInitialState;
			obj->name = name;
			if (!name.empty()) {
				namedEvents[name] = obj;
			}
		}
	}

	HANDLE handle = handles::allocDataHandle({handles::TYPE_EVENT, obj, 0});
	wibo::lastError = alreadyExists ? ERROR_ALREADY_EXISTS : ERROR_SUCCESS;
	return handle;
}

HANDLE WIN_FUNC CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState,
							 LPCSTR lpName) {
	DEBUG_LOG("CreateEventA -> ");
	std::vector<uint16_t> wideName;
	makeWideNameFromAnsi(lpName, wideName);
	return CreateEventW(lpEventAttributes, bManualReset, bInitialState,
						lpName ? reinterpret_cast<LPCWSTR>(wideName.data()) : nullptr);
}

HANDLE WIN_FUNC CreateSemaphoreW(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,
								 LPCWSTR lpName) {
	DEBUG_LOG("CreateSemaphoreW(%p, %ld, %ld, %ls)\n", lpSemaphoreAttributes, static_cast<long>(lInitialCount),
			  static_cast<long>(lMaximumCount), lpName ? reinterpret_cast<const wchar_t *>(lpName) : L"<null>");
	(void)lpSemaphoreAttributes;

	std::u16string name = makeMutexName(lpName);
	SemaphoreObject *obj = nullptr;
	bool alreadyExists = false;
	{
		std::lock_guard<std::mutex> lock(semaphoreRegistryLock);
		if (!name.empty()) {
			auto it = namedSemaphores.find(name);
			if (it != namedSemaphores.end()) {
				obj = it->second;
				obj->refCount++;
				alreadyExists = true;
			}
		}
		if (!obj) {
			if (lMaximumCount <= 0 || lInitialCount < 0 || lInitialCount > lMaximumCount) {
				wibo::lastError = ERROR_INVALID_PARAMETER;
				return nullptr;
			}
			obj = new SemaphoreObject();
			pthread_mutex_init(&obj->mutex, nullptr);
			pthread_cond_init(&obj->cond, nullptr);
			obj->count = lInitialCount;
			obj->maxCount = lMaximumCount;
			obj->name = name;
			if (!name.empty()) {
				namedSemaphores[name] = obj;
			}
		}
	}

	HANDLE handle = handles::allocDataHandle({handles::TYPE_SEMAPHORE, obj, 0});
	wibo::lastError = alreadyExists ? ERROR_ALREADY_EXISTS : ERROR_SUCCESS;
	return handle;
}

HANDLE WIN_FUNC CreateSemaphoreA(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,
								 LPCSTR lpName) {
	DEBUG_LOG("CreateSemaphoreA -> ");
	std::vector<uint16_t> wideName;
	makeWideNameFromAnsi(lpName, wideName);
	return CreateSemaphoreW(lpSemaphoreAttributes, lInitialCount, lMaximumCount,
							lpName ? reinterpret_cast<LPCWSTR>(wideName.data()) : nullptr);
}

BOOL WIN_FUNC ReleaseSemaphore(HANDLE hSemaphore, LONG lReleaseCount, PLONG lpPreviousCount) {
	DEBUG_LOG("ReleaseSemaphore(%p, %ld, %p)\n", hSemaphore, static_cast<long>(lReleaseCount), lpPreviousCount);
	if (lReleaseCount <= 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	SemaphoreObject *obj = semaphoreObjectFromHandle(hSemaphore);
	if (!obj) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	pthread_mutex_lock(&obj->mutex);
	if (lpPreviousCount) {
		*lpPreviousCount = obj->count;
	}
	if (lReleaseCount > obj->maxCount - obj->count) {
		pthread_mutex_unlock(&obj->mutex);
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	obj->count += lReleaseCount;
	pthread_mutex_unlock(&obj->mutex);
	pthread_cond_broadcast(&obj->cond);
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC SetEvent(HANDLE hEvent) {
	DEBUG_LOG("SetEvent(%p)\n", hEvent);
	if (!setEventSignaledState(hEvent, true)) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC ResetEvent(HANDLE hEvent) {
	DEBUG_LOG("ResetEvent(%p)\n", hEvent);
	if (!setEventSignaledState(hEvent, false)) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

DWORD WIN_FUNC WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
	DEBUG_LOG("WaitForSingleObject(%p, %u)\n", hHandle, dwMilliseconds);
	handles::Data data = handles::dataFromHandle(hHandle, false);
	switch (data.type) {
	case handles::TYPE_PROCESS: {
		if (dwMilliseconds != INFINITE) {
			DEBUG_LOG("WaitForSingleObject: timeout for process not supported\n");
			wibo::lastError = ERROR_NOT_SUPPORTED;
			return WAIT_FAILED;
		}
		auto *process = reinterpret_cast<processes::Process *>(data.ptr);
		int status = 0;
		for (;;) {
			if (waitpid(process->pid, &status, 0) == -1) {
				if (errno == EINTR) {
					continue;
				}
				if (errno == ECHILD && process->terminationRequested) {
					process->exitCode = process->forcedExitCode;
					break;
				}
				DEBUG_LOG("WaitForSingleObject: waitpid(%d) failed: %s\n", process->pid, strerror(errno));
				wibo::lastError = ERROR_INVALID_HANDLE;
				return WAIT_FAILED;
			}
			break;
		}
		if (process->terminationRequested) {
			process->exitCode = process->forcedExitCode;
		} else if (WIFEXITED(status)) {
			process->exitCode = static_cast<DWORD>(WEXITSTATUS(status));
		} else {
			DEBUG_LOG("WaitForSingleObject: child process exited abnormally - returning exit code 1\n");
			process->exitCode = 1;
		}
		process->terminationRequested = false;
		wibo::lastError = ERROR_SUCCESS;
		return WAIT_OBJECT_0;
	}
	case handles::TYPE_EVENT: {
		EventObject *obj = reinterpret_cast<EventObject *>(data.ptr);
		if (dwMilliseconds != INFINITE) {
			DEBUG_LOG("WaitForSingleObject: timeout for event not supported\n");
			wibo::lastError = ERROR_NOT_SUPPORTED;
			return WAIT_FAILED;
		}
		pthread_mutex_lock(&obj->mutex);
		while (!obj->signaled) {
			pthread_cond_wait(&obj->cond, &obj->mutex);
		}
		if (!obj->manualReset) {
			obj->signaled = false;
		}
		pthread_mutex_unlock(&obj->mutex);
		wibo::lastError = ERROR_SUCCESS;
		return WAIT_OBJECT_0;
	}
	case handles::TYPE_THREAD: {
		ThreadObject *obj = reinterpret_cast<ThreadObject *>(data.ptr);
		if (dwMilliseconds != INFINITE) {
			DEBUG_LOG("WaitForSingleObject: timeout for thread not supported\n");
			wibo::lastError = ERROR_NOT_SUPPORTED;
			return WAIT_FAILED;
		}
		pthread_mutex_lock(&obj->mutex);
		while (!obj->finished) {
			pthread_cond_wait(&obj->cond, &obj->mutex);
		}
		bool needJoin = !obj->joined && !obj->detached;
		pthread_t thread = obj->thread;
		if (needJoin) {
			obj->joined = true;
		}
		pthread_mutex_unlock(&obj->mutex);
		if (needJoin) {
			pthread_join(thread, nullptr);
		}
		wibo::lastError = ERROR_SUCCESS;
		return WAIT_OBJECT_0;
	}
	case handles::TYPE_SEMAPHORE: {
		SemaphoreObject *obj = reinterpret_cast<SemaphoreObject *>(data.ptr);
		if (dwMilliseconds != INFINITE) {
			DEBUG_LOG("WaitForSingleObject: timeout for semaphore not supported\n");
			wibo::lastError = ERROR_NOT_SUPPORTED;
			return WAIT_FAILED;
		}
		pthread_mutex_lock(&obj->mutex);
		while (obj->count == 0) {
			pthread_cond_wait(&obj->cond, &obj->mutex);
		}
		obj->count--;
		pthread_mutex_unlock(&obj->mutex);
		wibo::lastError = ERROR_SUCCESS;
		return WAIT_OBJECT_0;
	}
	case handles::TYPE_MUTEX: {
		MutexObject *obj = reinterpret_cast<MutexObject *>(data.ptr);
		if (dwMilliseconds != INFINITE) {
			DEBUG_LOG("WaitForSingleObject: timeout for mutex not supported\n");
			wibo::lastError = ERROR_NOT_SUPPORTED;
			return WAIT_FAILED;
		}
		pthread_mutex_lock(&obj->mutex);
		pthread_t self = pthread_self();
		if (obj->ownerValid && pthread_equal(obj->owner, self)) {
			obj->recursionCount++;
		} else {
			obj->owner = self;
			obj->ownerValid = true;
			obj->recursionCount = 1;
		}
		wibo::lastError = ERROR_SUCCESS;
		return WAIT_OBJECT_0;
	}
	default:
		DEBUG_LOG("WaitForSingleObject: unsupported handle type %d\n", data.type);
		wibo::lastError = ERROR_INVALID_HANDLE;
		return WAIT_FAILED;
	}
}

void WIN_FUNC InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
	VERBOSE_LOG("STUB: InitializeCriticalSection(%p)\n", lpCriticalSection);
	if (!lpCriticalSection) {
		return;
	}
	std::memset(lpCriticalSection, 0, sizeof(*lpCriticalSection));
}

BOOL WIN_FUNC InitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount, DWORD Flags) {
	DEBUG_LOG("STUB: InitializeCriticalSectionEx(%p, %u, 0x%x)\n", lpCriticalSection, dwSpinCount, Flags);
	if (!lpCriticalSection) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	if (Flags & ~CRITICAL_SECTION_NO_DEBUG_INFO) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	std::memset(lpCriticalSection, 0, sizeof(*lpCriticalSection));
	lpCriticalSection->SpinCount = dwSpinCount;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount) {
	DEBUG_LOG("STUB: InitializeCriticalSectionAndSpinCount(%p, %u)\n", lpCriticalSection, dwSpinCount);
	if (!lpCriticalSection) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	std::memset(lpCriticalSection, 0, sizeof(*lpCriticalSection));
	lpCriticalSection->SpinCount = dwSpinCount;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

void WIN_FUNC DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
	VERBOSE_LOG("STUB: DeleteCriticalSection(%p)\n", lpCriticalSection);
	(void)lpCriticalSection;
}

void WIN_FUNC EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
	VERBOSE_LOG("STUB: EnterCriticalSection(%p)\n", lpCriticalSection);
	(void)lpCriticalSection;
}

void WIN_FUNC LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
	VERBOSE_LOG("STUB: LeaveCriticalSection(%p)\n", lpCriticalSection);
	(void)lpCriticalSection;
}

BOOL WIN_FUNC InitOnceBeginInitialize(LPINIT_ONCE lpInitOnce, DWORD dwFlags, PBOOL fPending, LPVOID *lpContext) {
	DEBUG_LOG("STUB: InitOnceBeginInitialize(%p, %u, %p, %p)\n", lpInitOnce, dwFlags, fPending, lpContext);
	if (!lpInitOnce) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	if (dwFlags & ~(INIT_ONCE_CHECK_ONLY | INIT_ONCE_ASYNC)) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	if (fPending) {
		*fPending = TRUE;
	}
	if (lpContext) {
		*lpContext = nullptr;
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC InitOnceComplete(LPINIT_ONCE lpInitOnce, DWORD dwFlags, LPVOID lpContext) {
	DEBUG_LOG("STUB: InitOnceComplete(%p, %u, %p)\n", lpInitOnce, dwFlags, lpContext);
	if (!lpInitOnce) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	if ((dwFlags & INIT_ONCE_INIT_FAILED) && (dwFlags & INIT_ONCE_ASYNC)) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	wibo::lastError = ERROR_SUCCESS;
	(void)lpContext;
	return TRUE;
}

void WIN_FUNC AcquireSRWLockShared(PSRWLOCK SRWLock) { VERBOSE_LOG("STUB: AcquireSRWLockShared(%p)\n", SRWLock); }

void WIN_FUNC ReleaseSRWLockShared(PSRWLOCK SRWLock) { VERBOSE_LOG("STUB: ReleaseSRWLockShared(%p)\n", SRWLock); }

void WIN_FUNC AcquireSRWLockExclusive(PSRWLOCK SRWLock) { VERBOSE_LOG("STUB: AcquireSRWLockExclusive(%p)\n", SRWLock); }

void WIN_FUNC ReleaseSRWLockExclusive(PSRWLOCK SRWLock) { VERBOSE_LOG("STUB: ReleaseSRWLockExclusive(%p)\n", SRWLock); }

BOOLEAN WIN_FUNC TryAcquireSRWLockExclusive(PSRWLOCK SRWLock) {
	VERBOSE_LOG("STUB: TryAcquireSRWLockExclusive(%p)\n", SRWLock);
	return TRUE;
}

void resetOverlappedEvent(OVERLAPPED *ov) {
	if (!ov || !ov->hEvent) {
		return;
	}
	setEventSignaledState(ov->hEvent, false);
}

void signalOverlappedEvent(OVERLAPPED *ov) {
	if (!ov || !ov->hEvent) {
		return;
	}
	setEventSignaledState(ov->hEvent, true);
}

} // namespace kernel32
