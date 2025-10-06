#include "synchapi.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "handles.h"
#include "internal.h"
#include "strutil.h"

#include <chrono>
#include <cstring>
#include <mutex>
#include <pthread.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

std::u16string makeU16String(LPCWSTR name) {
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
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("Sleep(%u)\n", dwMilliseconds);
	usleep(static_cast<useconds_t>(dwMilliseconds) * 1000);
}

HANDLE WIN_FUNC CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CreateMutexW(%p, %d, %s)\n", lpMutexAttributes, static_cast<int>(bInitialOwner),
			  wideStringToString(lpName).c_str());
	std::u16string name = makeU16String(lpName);
	const uint32_t grantedAccess = MUTEX_ALL_ACCESS;
	uint32_t handleFlags = 0;
	if (lpMutexAttributes && lpMutexAttributes->bInheritHandle) {
		handleFlags |= HANDLE_FLAG_INHERIT;
	}
	auto [mu, created] = wibo::g_namespace.getOrCreate(name, [&]() {
		auto *mu = new MutexObject();
		if (bInitialOwner) {
			std::lock_guard lk(mu->m);
			mu->owner = pthread_self();
			mu->ownerValid = true;
			mu->recursionCount = 1;
			mu->signaled.store(false, std::memory_order_release);
		}
		return mu;
	});
	if (!mu) {
		// Name exists but isn't a mutex
		wibo::lastError = ERROR_INVALID_HANDLE;
		return nullptr;
	}
	HANDLE h = wibo::handles().alloc(std::move(mu), grantedAccess, handleFlags);
	wibo::lastError = created ? ERROR_SUCCESS : ERROR_ALREADY_EXISTS;
	return h;
}

HANDLE WIN_FUNC CreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CreateMutexA -> ");
	std::vector<uint16_t> wideName;
	makeWideNameFromAnsi(lpName, wideName);
	return CreateMutexW(lpMutexAttributes, bInitialOwner,
						lpName ? reinterpret_cast<LPCWSTR>(wideName.data()) : nullptr);
}

BOOL WIN_FUNC ReleaseMutex(HANDLE hMutex) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("ReleaseMutex(%p)\n", hMutex);
	auto mu = wibo::handles().getAs<MutexObject>(hMutex);
	if (!mu) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	const pthread_t self = pthread_self();
	bool notify = false;
	{
		std::lock_guard lk(mu->m);
		if (!mu->ownerValid || !pthread_equal(mu->owner, self) || mu->recursionCount == 0) {
			wibo::lastError = ERROR_NOT_OWNER;
			return FALSE;
		}
		if (--mu->recursionCount == 0) {
			mu->ownerValid = false;
			mu->signaled.store(true, std::memory_order_release);
			notify = true;
		}
	}
	if (notify) {
		mu->cv.notify_one();
	}
	return TRUE;
}

HANDLE WIN_FUNC CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState,
							 LPCWSTR lpName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CreateEventW(%p, %d, %d, %s)\n", lpEventAttributes, static_cast<int>(bManualReset),
			  static_cast<int>(bInitialState), wideStringToString(lpName).c_str());
	std::u16string name = makeU16String(lpName);
	const uint32_t grantedAccess = EVENT_ALL_ACCESS;
	uint32_t handleFlags = 0;
	if (lpEventAttributes && lpEventAttributes->bInheritHandle) {
		handleFlags |= HANDLE_FLAG_INHERIT;
	}
	auto [ev, created] = wibo::g_namespace.getOrCreate(name, [&]() {
		auto e = new EventObject(bManualReset);
		e->signaled.store(bInitialState, std::memory_order_relaxed);
		return e;
	});
	if (!ev) {
		// Name exists but isn't an event
		wibo::lastError = ERROR_INVALID_HANDLE;
		return nullptr;
	}
	HANDLE h = wibo::handles().alloc(std::move(ev), grantedAccess, handleFlags);
	DEBUG_LOG("-> %p (created=%d)\n", h, created ? 1 : 0);
	wibo::lastError = created ? ERROR_SUCCESS : ERROR_ALREADY_EXISTS;
	return h;
}

HANDLE WIN_FUNC CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState,
							 LPCSTR lpName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CreateEventA -> ");
	std::vector<uint16_t> wideName;
	makeWideNameFromAnsi(lpName, wideName);
	return CreateEventW(lpEventAttributes, bManualReset, bInitialState,
						lpName ? reinterpret_cast<LPCWSTR>(wideName.data()) : nullptr);
}

HANDLE WIN_FUNC CreateSemaphoreW(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,
								 LPCWSTR lpName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CreateSemaphoreW(%p, %ld, %ld, %s)\n", lpSemaphoreAttributes, lInitialCount, lMaximumCount,
			  wideStringToString(lpName).c_str());
	auto name = makeU16String(lpName);
	const uint32_t granted = SEMAPHORE_ALL_ACCESS;
	uint32_t hflags = 0;
	if (lpSemaphoreAttributes && lpSemaphoreAttributes->bInheritHandle) {
		hflags |= HANDLE_FLAG_INHERIT;
	}
	auto [sem, created] = wibo::g_namespace.getOrCreate(name, [&]() -> SemaphoreObject * {
		if (lMaximumCount <= 0 || lInitialCount < 0 || lInitialCount > lMaximumCount) {
			return nullptr;
		}
		return new SemaphoreObject(lInitialCount, lMaximumCount);
	});
	if (!sem) {
		// Name exists but isn't an event
		wibo::lastError = ERROR_INVALID_HANDLE;
		return nullptr;
	}
	HANDLE h = wibo::handles().alloc(std::move(sem), granted, hflags);
	wibo::lastError = created ? ERROR_SUCCESS : ERROR_ALREADY_EXISTS;
	return h;
}

HANDLE WIN_FUNC CreateSemaphoreA(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,
								 LPCSTR lpName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CreateSemaphoreA -> ");
	std::vector<uint16_t> wideName;
	makeWideNameFromAnsi(lpName, wideName);
	return CreateSemaphoreW(lpSemaphoreAttributes, lInitialCount, lMaximumCount,
							lpName ? reinterpret_cast<LPCWSTR>(wideName.data()) : nullptr);
}

BOOL WIN_FUNC ReleaseSemaphore(HANDLE hSemaphore, LONG lReleaseCount, PLONG lpPreviousCount) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("ReleaseSemaphore(%p, %ld, %p)\n", hSemaphore, lReleaseCount, lpPreviousCount);
	if (lReleaseCount < 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	auto sem = wibo::handles().getAs<SemaphoreObject>(hSemaphore);
	if (!sem) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}

	LONG prev = 0;
	{
		std::lock_guard lk(sem->m);
		if (lpPreviousCount) {
			prev = sem->count;
		}
		if (sem->count > sem->maxCount - lReleaseCount) {
			wibo::lastError = ERROR_TOO_MANY_POSTS;
			return FALSE;
		}
		sem->count += lReleaseCount;
		sem->signaled.store(sem->count > 0, std::memory_order_release);
	}
	for (LONG i = 0; i < lReleaseCount; ++i) {
		sem->cv.notify_one();
	}

	if (lpPreviousCount) {
		*lpPreviousCount = prev;
	}
	return TRUE;
}

BOOL WIN_FUNC SetEvent(HANDLE hEvent) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetEvent(%p)\n", hEvent);
	auto ev = wibo::handles().getAs<EventObject>(hEvent);
	if (!ev) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	ev->set();
	return TRUE;
}

BOOL WIN_FUNC ResetEvent(HANDLE hEvent) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("ResetEvent(%p)\n", hEvent);
	auto ev = wibo::handles().getAs<EventObject>(hEvent);
	if (!ev) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	ev->reset();
	return TRUE;
}

DWORD WIN_FUNC WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("WaitForSingleObject(%p, %u)\n", hHandle, dwMilliseconds);
	HandleMeta meta{};
	Pin<> obj = wibo::handles().get(hHandle, &meta);
	if (!obj) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		DEBUG_LOG("-> ERROR_INVALID_HANDLE\n");
		return WAIT_FAILED;
	}
#ifdef CHECK_ACCESS
	if ((meta.grantedAccess & SYNCHRONIZE) == 0) {
		wibo::lastError = ERROR_ACCESS_DENIED;
		DEBUG_LOG("!!! DENIED: 0x%x\n", meta.grantedAccess);
		return WAIT_FAILED;
	}
#endif

	auto doWait = [&](auto &lk, auto &cv, auto pred) -> bool {
		if (dwMilliseconds == INFINITE) {
			cv.wait(lk, pred);
			return true;
		} else {
			return cv.wait_for(lk, std::chrono::milliseconds(dwMilliseconds), pred);
		}
	};

	DEBUG_LOG("Waiting on object with type %d\n", static_cast<int>(obj->type));

	switch (obj->type) {
	case ObjectType::Event: {
		auto ev = std::move(obj).downcast<EventObject>();
		std::unique_lock lk(ev->m);
		bool ok = doWait(lk, ev->cv, [&] { return ev->signaled.load(std::memory_order_acquire); });
		if (!ok) {
			return WAIT_TIMEOUT;
		}
		if (!ev->manualReset) {
			ev->signaled.store(false, std::memory_order_release);
		}
		return WAIT_OBJECT_0;
	}
	case ObjectType::Semaphore: {
		auto sem = std::move(obj).downcast<SemaphoreObject>();
		std::unique_lock lk(sem->m);
		bool ok = doWait(lk, sem->cv, [&] { return sem->count > 0; });
		if (!ok) {
			return WAIT_TIMEOUT;
		}
		--sem->count;
		if (sem->count == 0) {
			sem->signaled.store(false, std::memory_order_release);
		}
		return WAIT_OBJECT_0;
	}
	case ObjectType::Mutex: {
		auto mu = std::move(obj).downcast<MutexObject>();
		pthread_t self = pthread_self();
		std::unique_lock lk(mu->m);
		// Recursive acquisition
		if (mu->ownerValid && pthread_equal(mu->owner, self)) {
			++mu->recursionCount;
			return WAIT_OBJECT_0;
		}
		bool ok = doWait(lk, mu->cv, [&] { return !mu->ownerValid || mu->abandoned; });
		if (!ok) {
			return WAIT_TIMEOUT;
		}
		DWORD ret = WAIT_OBJECT_0;
		if (std::exchange(mu->abandoned, false)) {
			// Acquire and report abandoned
			ret = WAIT_ABANDONED;
		}
		mu->owner = self;
		mu->ownerValid = true;
		mu->recursionCount = 1;
		mu->signaled.store(false, std::memory_order_release);
		return ret;
	}
	case ObjectType::Thread: {
		auto th = std::move(obj).downcast<ThreadObject>();
		pthread_t self = pthread_self();
		std::unique_lock lk(th->m);
		if (pthread_equal(th->thread, self)) {
			// Windows actually allows you to wait on your own thread, but why bother?
			return WAIT_TIMEOUT;
		}
		bool ok = doWait(lk, th->cv, [&] { return th->signaled.load(std::memory_order_acquire); });
		return ok ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
	}
	case ObjectType::Process: {
		auto po = std::move(obj).downcast<ProcessObject>();
		std::unique_lock lk(po->m);
		if (po->pidfd == -1) {
			// Windows actually allows you to wait on your own process, but why bother?
			return WAIT_TIMEOUT;
		}
		bool ok = doWait(lk, po->cv, [&] { return po->signaled.load(std::memory_order_acquire); });
		return ok ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
	}
	default:
		wibo::lastError = ERROR_INVALID_HANDLE;
		return WAIT_FAILED;
	}
}

void WIN_FUNC InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("STUB: InitializeCriticalSection(%p)\n", lpCriticalSection);
	if (!lpCriticalSection) {
		return;
	}
	std::memset(lpCriticalSection, 0, sizeof(*lpCriticalSection));
}

BOOL WIN_FUNC InitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount, DWORD Flags) {
	HOST_CONTEXT_GUARD();
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
	return TRUE;
}

BOOL WIN_FUNC InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: InitializeCriticalSectionAndSpinCount(%p, %u)\n", lpCriticalSection, dwSpinCount);
	if (!lpCriticalSection) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	std::memset(lpCriticalSection, 0, sizeof(*lpCriticalSection));
	lpCriticalSection->SpinCount = dwSpinCount;
	return TRUE;
}

void WIN_FUNC DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("STUB: DeleteCriticalSection(%p)\n", lpCriticalSection);
	(void)lpCriticalSection;
}

void WIN_FUNC EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("STUB: EnterCriticalSection(%p)\n", lpCriticalSection);
	(void)lpCriticalSection;
}

void WIN_FUNC LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("STUB: LeaveCriticalSection(%p)\n", lpCriticalSection);
	(void)lpCriticalSection;
}

BOOL WIN_FUNC InitOnceBeginInitialize(LPINIT_ONCE lpInitOnce, DWORD dwFlags, PBOOL fPending, LPVOID *lpContext) {
	HOST_CONTEXT_GUARD();
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
	return TRUE;
}

BOOL WIN_FUNC InitOnceComplete(LPINIT_ONCE lpInitOnce, DWORD dwFlags, LPVOID lpContext) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: InitOnceComplete(%p, %u, %p)\n", lpInitOnce, dwFlags, lpContext);
	if (!lpInitOnce) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	if ((dwFlags & INIT_ONCE_INIT_FAILED) && (dwFlags & INIT_ONCE_ASYNC)) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	(void)lpContext;
	return TRUE;
}

void WIN_FUNC AcquireSRWLockShared(PSRWLOCK SRWLock) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("STUB: AcquireSRWLockShared(%p)\n", SRWLock);
}

void WIN_FUNC ReleaseSRWLockShared(PSRWLOCK SRWLock) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("STUB: ReleaseSRWLockShared(%p)\n", SRWLock);
}

void WIN_FUNC AcquireSRWLockExclusive(PSRWLOCK SRWLock) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("STUB: AcquireSRWLockExclusive(%p)\n", SRWLock);
}

void WIN_FUNC ReleaseSRWLockExclusive(PSRWLOCK SRWLock) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("STUB: ReleaseSRWLockExclusive(%p)\n", SRWLock);
}

BOOLEAN WIN_FUNC TryAcquireSRWLockExclusive(PSRWLOCK SRWLock) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("STUB: TryAcquireSRWLockExclusive(%p)\n", SRWLock);
	return TRUE;
}

} // namespace kernel32
