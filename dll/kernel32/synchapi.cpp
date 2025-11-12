#include "synchapi.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "handles.h"
#include "heap.h"
#include "interlockedapi.h"
#include "internal.h"
#include "processthreadsapi.h"
#include "strutil.h"
#include "types.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <memory>
#include <mutex>
#include <optional>
#include <pthread.h>
#include <string>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

constexpr DWORD kSrwLockExclusive = 0x1u;
constexpr DWORD kSrwLockSharedIncrement = 0x2u;
constexpr GUEST_PTR kInitOnceStateMask = 0x3u;
constexpr GUEST_PTR kInitOnceCompletedFlag = 0x2u;
constexpr GUEST_PTR kInitOnceReservedMask = (1u << INIT_ONCE_CTX_RESERVED_BITS) - 1;
constexpr size_t kSupportedAddressSizes = 4; // 1, 2, 4, 8 bytes

struct AddressWaitQueue {
	std::mutex mutex;
	std::condition_variable cv;
	size_t waiterCount = 0;
	std::array<size_t, kSupportedAddressSizes> sizeCounts{};
};

std::mutex g_waitAddressMutex;
std::unordered_map<void *, std::weak_ptr<AddressWaitQueue>> g_waitAddressQueues;

constexpr size_t sizeToIndex(size_t size) {
	size_t index = __builtin_ctz(size);
	return index >= kSupportedAddressSizes ? -1 : index;
}

std::shared_ptr<AddressWaitQueue> getWaitQueue(void *address) {
	std::lock_guard lk(g_waitAddressMutex);
	auto &slot = g_waitAddressQueues[address];
	auto queue = slot.lock();
	if (!queue) {
		queue = std::make_shared<AddressWaitQueue>();
		slot = queue;
	}
	return queue;
}

std::shared_ptr<AddressWaitQueue> tryGetWaitQueue(void *address) {
	std::lock_guard lk(g_waitAddressMutex);
	auto it = g_waitAddressQueues.find(address);
	if (it == g_waitAddressQueues.end()) {
		return nullptr;
	}
	auto queue = it->second.lock();
	if (!queue) {
		g_waitAddressQueues.erase(it);
		return nullptr;
	}
	return queue;
}

void cleanupWaitQueue(void *address, const std::shared_ptr<AddressWaitQueue> &queue) {
	std::lock_guard lk(g_waitAddressMutex);
	auto it = g_waitAddressQueues.find(address);
	if (it == g_waitAddressQueues.end()) {
		return;
	}
	auto locked = it->second.lock();
	if (!locked) {
		g_waitAddressQueues.erase(it);
		return;
	}
	if (locked.get() != queue.get()) {
		return;
	}
	std::lock_guard queueLock(queue->mutex);
	if (queue->waiterCount == 0) {
		g_waitAddressQueues.erase(it);
	}
}

struct WaitRegistration {
	void *address;
	std::shared_ptr<AddressWaitQueue> queue;
	size_t sizeIndex;
	bool registered = false;

	WaitRegistration(void *addr, std::shared_ptr<AddressWaitQueue> q, size_t idx)
		: address(addr), queue(std::move(q)), sizeIndex(idx) {}

	void registerWaiter() {
		if (!queue) {
			return;
		}
		std::lock_guard lk(queue->mutex);
		queue->waiterCount++;
		queue->sizeCounts[sizeIndex]++;
		registered = true;
	}

	void unregister() {
		if (!queue || !registered) {
			return;
		}
		std::lock_guard lk(queue->mutex);
		queue->waiterCount--;
		queue->sizeCounts[sizeIndex]--;
		registered = false;
	}

	~WaitRegistration() {
		unregister();
		if (queue) {
			cleanupWaitQueue(address, queue);
		}
	}
};

#if defined(__APPLE__)

using LibcppMonitorFn = long long (*)(const void volatile *);
using LibcppWaitFn = void (*)(const void volatile *, long long);
using LibcppNotifyFn = void (*)(const void volatile *);

LibcppMonitorFn getLibcppAtomicMonitor() {
	static LibcppMonitorFn fn =
		reinterpret_cast<LibcppMonitorFn>(dlsym(RTLD_DEFAULT, "_ZNSt3__123__libcpp_atomic_monitorEPVKv"));
	return fn;
}

LibcppWaitFn getLibcppAtomicWait() {
	static LibcppWaitFn fn =
		reinterpret_cast<LibcppWaitFn>(dlsym(RTLD_DEFAULT, "_ZNSt3__120__libcpp_atomic_waitEPVKvx"));
	return fn;
}

LibcppNotifyFn getLibcppAtomicNotifyOne() {
	static LibcppNotifyFn fn =
		reinterpret_cast<LibcppNotifyFn>(dlsym(RTLD_DEFAULT, "_ZNSt3__123__cxx_atomic_notify_oneEPVKv"));
	return fn;
}

LibcppNotifyFn getLibcppAtomicNotifyAll() {
	static LibcppNotifyFn fn =
		reinterpret_cast<LibcppNotifyFn>(dlsym(RTLD_DEFAULT, "_ZNSt3__123__cxx_atomic_notify_allEPVKv"));
	return fn;
}

template <typename T> void platformWaitIndefinite(T volatile *address, T expected) {
	auto monitorFn = getLibcppAtomicMonitor();
	auto waitFn = getLibcppAtomicWait();
	if (!monitorFn || !waitFn) {
		while (__atomic_load_n(address, __ATOMIC_ACQUIRE) == expected) {
			std::this_thread::sleep_for(std::chrono::microseconds(50));
		}
		return;
	}
	while (true) {
		T current = __atomic_load_n(address, __ATOMIC_ACQUIRE);
		if (current != expected) {
			return;
		}
		auto monitor = monitorFn(address);
		current = __atomic_load_n(address, __ATOMIC_ACQUIRE);
		if (current != expected) {
			continue;
		}
		waitFn(address, monitor);
	}
}

inline void platformNotifyAddress(void *address, size_t, bool wakeOne) {
	auto notifyFn = wakeOne ? getLibcppAtomicNotifyOne() : getLibcppAtomicNotifyAll();
	if (notifyFn) {
		notifyFn(address);
	}
}

#else

template <typename T> void platformWaitIndefinite(T volatile *address, T expected) {
	std::atomic_ref<T> ref(*const_cast<T *>(address));
	ref.wait(expected, std::memory_order_relaxed);
}

template <typename T> void atomicNotify(void *address, bool wakeOne) {
	auto *typed = reinterpret_cast<T *>(address);
	std::atomic_ref<T> ref(*typed);
	if (wakeOne) {
		ref.notify_one();
	} else {
		ref.notify_all();
	}
}

inline void platformNotifyAddress(void *address, size_t size, bool wakeOne) {
	switch (size) {
	case 1:
		atomicNotify<uint8_t>(address, wakeOne);
		break;
	case 2:
		atomicNotify<uint16_t>(address, wakeOne);
		break;
	case 4:
		atomicNotify<uint32_t>(address, wakeOne);
		break;
	case 8:
		atomicNotify<uint64_t>(address, wakeOne);
		break;
	default:
		break;
	}
}

#endif

void notifyAtomicWaiters(void *address, const std::array<size_t, kSupportedAddressSizes> &sizeCounts, bool wakeOne) {
	uintptr_t addrValue = reinterpret_cast<uintptr_t>(address);
	for (size_t i = 0; i < sizeCounts.size(); ++i) {
		if (sizeCounts[i] == 0) {
			continue;
		}
		size_t size = 1 << i;
		if (addrValue & (size - 1)) {
			continue;
		}
		platformNotifyAddress(address, size, wakeOne);
	}
}

template <typename T> bool waitOnAddressTyped(VOID volatile *addressVoid, PVOID comparePtr, DWORD dwMilliseconds) {
	auto *address = reinterpret_cast<T volatile *>(addressVoid);
	if (!address) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return false;
	}
	if (reinterpret_cast<uintptr_t>(address) % alignof(T) != 0) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return false;
	}

	const T compareValue = *reinterpret_cast<const T *>(comparePtr);
	if (__atomic_load_n(address, __ATOMIC_ACQUIRE) != compareValue) {
		return true;
	}

	if (dwMilliseconds == 0) {
		kernel32::setLastError(ERROR_TIMEOUT);
		return false;
	}

	void *queueKey = const_cast<void *>(addressVoid);
	auto queue = getWaitQueue(queueKey);
	if (!queue) {
		kernel32::setLastError(ERROR_GEN_FAILURE);
		return false;
	}

	int sizeIdx = sizeToIndex(sizeof(T));
	DEBUG_LOG("size: %d, index %d\n", sizeof(T), sizeIdx);
	if (sizeIdx < 0) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return false;
	}

	WaitRegistration registration(queueKey, queue, static_cast<size_t>(sizeIdx));
	registration.registerWaiter();

	if (dwMilliseconds == INFINITE) {
		while (__atomic_load_n(address, __ATOMIC_ACQUIRE) == compareValue) {
			platformWaitIndefinite(address, compareValue);
		}
		return true;
	}

	const auto deadline =
		std::chrono::steady_clock::now() + std::chrono::milliseconds(static_cast<uint64_t>(dwMilliseconds));
	bool timedOut = false;
	{
		std::unique_lock lk(queue->mutex);
		while (__atomic_load_n(address, __ATOMIC_ACQUIRE) == compareValue) {
			if (queue->cv.wait_until(lk, deadline) == std::cv_status::timeout) {
				if (__atomic_load_n(address, __ATOMIC_ACQUIRE) == compareValue) {
					timedOut = true;
					break;
				}
			}
		}
	}
	if (timedOut && __atomic_load_n(address, __ATOMIC_ACQUIRE) == compareValue) {
		kernel32::setLastError(ERROR_TIMEOUT);
		return false;
	}
	return true;
}

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

struct WaitBlock {
	explicit WaitBlock(bool waitAllIn, DWORD count) : waitAll(waitAllIn != FALSE), satisfied(count, false) {}

	static void notify(void *context, WaitableObject *obj, DWORD index, bool abandoned) {
		auto *self = static_cast<WaitBlock *>(context);
		if (self) {
			self->handleSignal(obj, index, abandoned, true);
		}
	}

	void noteInitial(WaitableObject *obj, DWORD index, bool abandoned) { handleSignal(obj, index, abandoned, false); }

	bool isCompleted(DWORD &outResult) {
		std::lock_guard lk(mutex);
		if (!completed) {
			return false;
		}
		outResult = result;
		return true;
	}

	bool waitUntil(const std::optional<std::chrono::steady_clock::time_point> &deadline, DWORD &outResult) {
		std::unique_lock lk(mutex);
		if (!completed) {
			if (deadline) {
				if (!cv.wait_until(lk, *deadline, [&] { return completed; })) {
					return false;
				}
			} else {
				cv.wait(lk, [&] { return completed; });
			}
		}
		outResult = result;
		return true;
	}

	void handleSignal(WaitableObject *obj, DWORD index, bool abandoned, bool fromWaiter) {
		if (!obj) {
			return;
		}
		bool notify = false;
		{
			std::lock_guard lk(mutex);
			if (index >= satisfied.size()) {
				return;
			}
			if (satisfied[index]) {
				// Already satisfied; nothing to do aside from cleanup below.
			} else if (!completed) {
				satisfied[index] = true;
				if (waitAll) {
					if (abandoned) {
						result = WAIT_ABANDONED + index;
						completed = true;
						notify = true;
					} else if (std::all_of(satisfied.begin(), satisfied.end(), [](bool v) { return v; })) {
						result = WAIT_OBJECT_0;
						completed = true;
						notify = true;
					}
				} else {
					result = abandoned ? (WAIT_ABANDONED + index) : (WAIT_OBJECT_0 + index);
					completed = true;
					notify = true;
				}
			}
		}
		// Always unregister once we've observed a signal for this waiter.
		if (fromWaiter) {
			obj->unregisterWaiter(this);
		} else if (!waitAll || satisfied[index]) {
			// Initial state satisfaction can drop registration immediately.
			obj->unregisterWaiter(this);
		}
		if (notify) {
			cv.notify_all();
		}
	}

	const bool waitAll;
	std::vector<bool> satisfied;
	bool completed = false;
	DWORD result = WAIT_TIMEOUT;
	std::mutex mutex;
	std::condition_variable cv;
};

struct InitOnceState {
	std::mutex mutex;
	std::condition_variable cv;
	bool completed = false;
	bool success = false;
	GUEST_PTR context = GUEST_NULL;
};

std::mutex g_initOnceMutex;
std::unordered_map<LPINIT_ONCE, std::shared_ptr<InitOnceState>> g_initOnceStates;

void insertInitOnceState(LPINIT_ONCE once, const std::shared_ptr<InitOnceState> &state) {
	std::lock_guard lk(g_initOnceMutex);
	g_initOnceStates[once] = state;
}

std::shared_ptr<InitOnceState> getInitOnceState(LPINIT_ONCE once) {
	std::lock_guard lk(g_initOnceMutex);
	auto it = g_initOnceStates.find(once);
	if (it == g_initOnceStates.end()) {
		return nullptr;
	}
	return it->second;
}

void eraseInitOnceState(LPINIT_ONCE once) {
	std::lock_guard lk(g_initOnceMutex);
	g_initOnceStates.erase(once);
}

inline DWORD owningThreadId(LPCRITICAL_SECTION crit) { return __atomic_load_n(&crit->OwningThread, __ATOMIC_ACQUIRE); }

inline void setOwningThread(LPCRITICAL_SECTION crit, DWORD threadId) {
	__atomic_store_n(&crit->OwningThread, threadId, __ATOMIC_RELEASE);
}

void waitForCriticalSection(LPCRITICAL_SECTION cs) {
	auto *sequence = reinterpret_cast<LONG volatile *>(&cs->LockSemaphore);
	LONG observed = __atomic_load_n(sequence, __ATOMIC_ACQUIRE);
	while (owningThreadId(cs) != 0) {
		kernel32::WaitOnAddress(sequence, &observed, sizeof(observed), INFINITE);
		observed = __atomic_load_n(sequence, __ATOMIC_ACQUIRE);
	}
}

void signalCriticalSection(LPCRITICAL_SECTION cs) {
	auto *sequence = reinterpret_cast<LONG *>(&cs->LockSemaphore);
	kernel32::InterlockedIncrement(const_cast<LONG volatile *>(sequence));
	kernel32::WakeByAddressSingle(sequence);
}

inline bool trySpinAcquireCriticalSection(LPCRITICAL_SECTION cs, DWORD threadId) {
	if (!cs || cs->SpinCount == 0) {
		return false;
	}
	for (ULONG_PTR spins = cs->SpinCount; spins > 0; --spins) {
		if (kernel32::TryEnterCriticalSection(cs)) {
			return true;
		}
		if (cs->LockCount > 0) {
			break;
		}
		std::this_thread::yield();
		if (owningThreadId(cs) == threadId) {
			// Owner is self, TryEnter would have succeeded; bail out.
			break;
		}
	}
	return false;
}

} // namespace

namespace kernel32 {

void WINAPI Sleep(DWORD dwMilliseconds) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("Sleep(%u)\n", dwMilliseconds);
	usleep(static_cast<useconds_t>(dwMilliseconds) * 1000);
}

HANDLE WINAPI CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName) {
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
			mu->signaled = false;
		}
		return mu;
	});
	if (!mu) {
		// Name exists but isn't a mutex
		setLastError(ERROR_INVALID_HANDLE);
		return NO_HANDLE;
	}
	HANDLE h = wibo::handles().alloc(std::move(mu), grantedAccess, handleFlags);
	setLastError(created ? ERROR_SUCCESS : ERROR_ALREADY_EXISTS);
	return h;
}

HANDLE WINAPI CreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CreateMutexA -> ");
	std::vector<uint16_t> wideName;
	makeWideNameFromAnsi(lpName, wideName);
	return CreateMutexW(lpMutexAttributes, bInitialOwner,
						lpName ? reinterpret_cast<LPCWSTR>(wideName.data()) : nullptr);
}

BOOL WINAPI ReleaseMutex(HANDLE hMutex) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("ReleaseMutex(%p)\n", hMutex);
	auto mu = wibo::handles().getAs<MutexObject>(hMutex);
	if (!mu) {
		setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	const pthread_t self = pthread_self();
	bool notify = false;
	{
		std::lock_guard lk(mu->m);
		if (!mu->ownerValid || !pthread_equal(mu->owner, self) || mu->recursionCount == 0) {
			setLastError(ERROR_NOT_OWNER);
			return FALSE;
		}
		if (--mu->recursionCount == 0) {
			mu->ownerValid = false;
			mu->signaled = true;
			notify = true;
		}
	}
	if (notify) {
		mu->cv.notify_one();
		mu->notifyWaiters(false);
	}
	return TRUE;
}

HANDLE WINAPI CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState,
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
		e->signaled = bInitialState;
		return e;
	});
	if (!ev) {
		// Name exists but isn't an event
		setLastError(ERROR_INVALID_HANDLE);
		return NO_HANDLE;
	}
	HANDLE h = wibo::handles().alloc(std::move(ev), grantedAccess, handleFlags);
	DEBUG_LOG("-> %p (created=%d)\n", h, created ? 1 : 0);
	setLastError(created ? ERROR_SUCCESS : ERROR_ALREADY_EXISTS);
	return h;
}

HANDLE WINAPI CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState,
						   LPCSTR lpName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CreateEventA -> ");
	std::vector<uint16_t> wideName;
	makeWideNameFromAnsi(lpName, wideName);
	return CreateEventW(lpEventAttributes, bManualReset, bInitialState,
						lpName ? reinterpret_cast<LPCWSTR>(wideName.data()) : nullptr);
}

HANDLE WINAPI CreateSemaphoreW(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,
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
		setLastError(ERROR_INVALID_HANDLE);
		return NO_HANDLE;
	}
	HANDLE h = wibo::handles().alloc(std::move(sem), granted, hflags);
	setLastError(created ? ERROR_SUCCESS : ERROR_ALREADY_EXISTS);
	return h;
}

HANDLE WINAPI CreateSemaphoreA(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,
							   LPCSTR lpName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CreateSemaphoreA -> ");
	std::vector<uint16_t> wideName;
	makeWideNameFromAnsi(lpName, wideName);
	return CreateSemaphoreW(lpSemaphoreAttributes, lInitialCount, lMaximumCount,
							lpName ? reinterpret_cast<LPCWSTR>(wideName.data()) : nullptr);
}

BOOL WINAPI ReleaseSemaphore(HANDLE hSemaphore, LONG lReleaseCount, PLONG lpPreviousCount) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("ReleaseSemaphore(%p, %ld, %p)\n", hSemaphore, lReleaseCount, lpPreviousCount);
	if (lReleaseCount < 0) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	auto sem = wibo::handles().getAs<SemaphoreObject>(hSemaphore);
	if (!sem) {
		setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}

	LONG prev = 0;
	bool shouldNotifyWaitBlocks = false;
	{
		std::lock_guard lk(sem->m);
		if (lpPreviousCount) {
			prev = sem->count;
		}
		if (sem->count > sem->maxCount - lReleaseCount) {
			setLastError(ERROR_TOO_MANY_POSTS);
			return FALSE;
		}
		sem->count += lReleaseCount;
		sem->signaled = sem->count > 0;
		shouldNotifyWaitBlocks = sem->count > 0;
	}
	for (LONG i = 0; i < lReleaseCount; ++i) {
		sem->cv.notify_one();
	}
	if (shouldNotifyWaitBlocks) {
		sem->notifyWaiters(false);
	}

	if (lpPreviousCount) {
		*lpPreviousCount = prev;
	}
	return TRUE;
}

BOOL WINAPI SetEvent(HANDLE hEvent) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetEvent(%p)\n", hEvent);
	auto ev = wibo::handles().getAs<EventObject>(hEvent);
	if (!ev) {
		setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	ev->set();
	return TRUE;
}

BOOL WINAPI ResetEvent(HANDLE hEvent) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("ResetEvent(%p)\n", hEvent);
	auto ev = wibo::handles().getAs<EventObject>(hEvent);
	if (!ev) {
		setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	ev->reset();
	return TRUE;
}

DWORD WINAPI WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("WaitForSingleObject(%p, %u)\n", hHandle, dwMilliseconds);
	HandleMeta meta{};
	Pin<> obj = wibo::handles().get(hHandle, &meta);
	if (!obj) {
		setLastError(ERROR_INVALID_HANDLE);
		DEBUG_LOG("-> ERROR_INVALID_HANDLE\n");
		return WAIT_FAILED;
	}
#ifdef CHECK_ACCESS
	if ((meta.grantedAccess & SYNCHRONIZE) == 0) {
		setLastError(ERROR_ACCESS_DENIED);
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
		bool ok = doWait(lk, ev->cv, [&] { return ev->signaled; });
		if (!ok) {
			return WAIT_TIMEOUT;
		}
		if (!ev->manualReset) {
			ev->signaled = false;
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
			sem->signaled = false;
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
		mu->signaled = false;
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
		bool ok = doWait(lk, th->cv, [&] { return th->signaled; });
		return ok ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
	}
	case ObjectType::Process: {
		auto po = std::move(obj).downcast<ProcessObject>();
		std::unique_lock lk(po->m);
		if (!po->signaled && !po->waitable) {
			// Windows actually allows you to wait on your own process, but why bother?
			return WAIT_TIMEOUT;
		}
		if (po->signaled) {
			return WAIT_OBJECT_0;
		}
		bool ok = doWait(lk, po->cv, [&] { return po->signaled; });
		return ok ? WAIT_OBJECT_0 : WAIT_TIMEOUT;
	}
	default:
		setLastError(ERROR_INVALID_HANDLE);
		return WAIT_FAILED;
	}
}

DWORD WINAPI WaitForMultipleObjects(DWORD nCount, const HANDLE *lpHandles, BOOL bWaitAll, DWORD dwMilliseconds) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("WaitForMultipleObjects(%u, %p, %d, %u)\n", nCount, lpHandles, static_cast<int>(bWaitAll),
			  dwMilliseconds);

	if (nCount == 0 || nCount > MAXIMUM_WAIT_OBJECTS || !lpHandles) {
		setLastError(ERROR_INVALID_PARAMETER);
		return WAIT_FAILED;
	}

	std::vector<Pin<WaitableObject>> objects(nCount);
	for (DWORD i = 0; i < nCount; ++i) {
		HandleMeta meta{};
		auto obj = wibo::handles().getAs<WaitableObject>(lpHandles[i], &meta);
		if (!obj) {
			setLastError(ERROR_INVALID_HANDLE);
			return WAIT_FAILED;
		}
		objects[i] = std::move(obj);
	}

	WaitBlock block(bWaitAll, nCount);
	for (DWORD i = 0; i < objects.size(); ++i) {
		objects[i]->registerWaiter(&block, i, &WaitBlock::notify);
	}

	for (DWORD i = 0; i < objects.size(); ++i) {
		auto *obj = objects[i].get();
		bool isSignaled = obj->signaled;
		bool isAbandoned = false;
		if (auto *mu = detail::castTo<MutexObject>(obj)) {
			isAbandoned = mu->abandoned;
		}
		if (isSignaled) {
			block.noteInitial(obj, i, isAbandoned);
		}
	}

	DWORD waitResult = WAIT_TIMEOUT;
	if (!block.isCompleted(waitResult)) {
		if (dwMilliseconds == 0) {
			waitResult = WAIT_TIMEOUT;
		} else {
			std::optional<std::chrono::steady_clock::time_point> deadline;
			if (dwMilliseconds != INFINITE) {
				deadline =
					std::chrono::steady_clock::now() + std::chrono::milliseconds(static_cast<uint64_t>(dwMilliseconds));
			}
			DWORD signaledResult = WAIT_TIMEOUT;
			bool completed = block.waitUntil(deadline, signaledResult);
			if (completed) {
				waitResult = signaledResult;
			} else {
				waitResult = WAIT_TIMEOUT;
			}
		}
	}

	for (const auto &object : objects) {
		object->unregisterWaiter(&block);
	}

	if (waitResult == WAIT_TIMEOUT) {
		return WAIT_TIMEOUT;
	}

	if (waitResult == WAIT_FAILED) {
		return WAIT_FAILED;
	}

	auto consume = [&](DWORD index) {
		if (index < nCount) {
			WaitForSingleObject(lpHandles[index], 0);
		}
	};

	if (bWaitAll) {
		if (waitResult == WAIT_OBJECT_0) {
			for (DWORD i = 0; i < nCount; ++i) {
				consume(i);
			}
		} else if (waitResult >= WAIT_ABANDONED && waitResult < WAIT_ABANDONED + nCount) {
			consume(waitResult - WAIT_ABANDONED);
		}
	} else {
		if (waitResult >= WAIT_OBJECT_0 && waitResult < WAIT_OBJECT_0 + nCount) {
			consume(waitResult - WAIT_OBJECT_0);
		} else if (waitResult >= WAIT_ABANDONED && waitResult < WAIT_ABANDONED + nCount) {
			consume(waitResult - WAIT_ABANDONED);
		}
	}

	return waitResult;
}

BOOL WINAPI WaitOnAddress(VOID volatile *Address, PVOID CompareAddress, SIZE_T AddressSize, DWORD dwMilliseconds) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("WaitOnAddress(%p, %p, %zu, %u)\n", Address, CompareAddress, AddressSize, dwMilliseconds);
	if (!Address || !CompareAddress) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	BOOL result = FALSE;
	switch (sizeToIndex(AddressSize)) {
	case 0:
		result = waitOnAddressTyped<uint8_t>(Address, CompareAddress, dwMilliseconds) ? TRUE : FALSE;
		break;
	case 1:
		result = waitOnAddressTyped<uint16_t>(Address, CompareAddress, dwMilliseconds) ? TRUE : FALSE;
		break;
	case 2:
		result = waitOnAddressTyped<uint32_t>(Address, CompareAddress, dwMilliseconds) ? TRUE : FALSE;
		break;
	case 3:
		result = waitOnAddressTyped<uint64_t>(Address, CompareAddress, dwMilliseconds) ? TRUE : FALSE;
		break;
	default:
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	return result;
}

void WINAPI WakeByAddressSingle(PVOID Address) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("WakeByAddressSingle(%p)\n", Address);
	if (!Address) {
		return;
	}
	std::array<size_t, kSupportedAddressSizes> sizeCounts{};
	auto queue = tryGetWaitQueue(Address);
	if (queue) {
		std::lock_guard lk(queue->mutex);
		sizeCounts = queue->sizeCounts;
	}
	notifyAtomicWaiters(Address, sizeCounts, true);
	if (queue) {
		queue->cv.notify_one();
	}
}

void WINAPI WakeByAddressAll(PVOID Address) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("WakeByAddressAll(%p)\n", Address);
	if (!Address) {
		return;
	}
	std::array<size_t, kSupportedAddressSizes> sizeCounts{};
	auto queue = tryGetWaitQueue(Address);
	if (queue) {
		std::lock_guard lk(queue->mutex);
		sizeCounts = queue->sizeCounts;
	}
	notifyAtomicWaiters(Address, sizeCounts, false);
	if (queue) {
		queue->cv.notify_all();
	}
}

void WINAPI InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("InitializeCriticalSection(%p)\n", lpCriticalSection);
	InitializeCriticalSectionEx(lpCriticalSection, 0, 0);
}

BOOL WINAPI InitializeCriticalSectionEx(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount, DWORD Flags) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("InitializeCriticalSectionEx(%p, %u, 0x%x)\n", lpCriticalSection, dwSpinCount, Flags);
	if (!lpCriticalSection) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	std::memset(lpCriticalSection, 0, sizeof(*lpCriticalSection));
	if (Flags & RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO) {
		lpCriticalSection->DebugInfo = static_cast<GUEST_PTR>(-1);
	} else {
		auto *debugInfo = reinterpret_cast<RTL_CRITICAL_SECTION_DEBUG *>(
			wibo::heap::guestCalloc(1, sizeof(RTL_CRITICAL_SECTION_DEBUG)));
		debugInfo->CriticalSection = toGuestPtr(lpCriticalSection);
		debugInfo->ProcessLocksList.Blink = toGuestPtr(&debugInfo->ProcessLocksList);
		debugInfo->ProcessLocksList.Flink = toGuestPtr(&debugInfo->ProcessLocksList);
		lpCriticalSection->DebugInfo = toGuestPtr(debugInfo);
	}
	lpCriticalSection->LockCount = -1;
	lpCriticalSection->SpinCount = dwSpinCount;
	return TRUE;
}

BOOL WINAPI InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("InitializeCriticalSectionAndSpinCount(%p, %u)\n", lpCriticalSection, dwSpinCount);
	InitializeCriticalSectionEx(lpCriticalSection, dwSpinCount, 0);
	return TRUE;
}

void WINAPI DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("DeleteCriticalSection(%p)\n", lpCriticalSection);
	if (!lpCriticalSection) {
		return;
	}

	if (lpCriticalSection->DebugInfo && lpCriticalSection->DebugInfo != static_cast<GUEST_PTR>(-1)) {
		auto *debugInfo = fromGuestPtr<RTL_CRITICAL_SECTION_DEBUG>(lpCriticalSection->DebugInfo);
		if (debugInfo && debugInfo->Spare[0] == 0) {
			wibo::heap::guestFree(debugInfo);
		}
	}

	lpCriticalSection->DebugInfo = GUEST_NULL;
	lpCriticalSection->RecursionCount = 0;
	lpCriticalSection->SpinCount = 0;
	setOwningThread(lpCriticalSection, 0);

	auto *sequence = reinterpret_cast<LONG *>(&lpCriticalSection->LockSemaphore);
	kernel32::InterlockedExchange(const_cast<LONG volatile *>(sequence), 0);
	kernel32::WakeByAddressAll(sequence);

	auto *lockCount = reinterpret_cast<LONG *>(&lpCriticalSection->LockCount);
	kernel32::InterlockedExchange(const_cast<LONG volatile *>(lockCount), -1);
	kernel32::WakeByAddressAll(lockCount);
}

BOOL WINAPI TryEnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("TryEnterCriticalSection(%p)\n", lpCriticalSection);
	if (!lpCriticalSection) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	auto *lockCount = const_cast<LONG volatile *>(&lpCriticalSection->LockCount);
	const DWORD threadId = GetCurrentThreadId();

	LONG previous = kernel32::InterlockedCompareExchange(lockCount, 0, -1);
	if (previous == -1) {
		setOwningThread(lpCriticalSection, threadId);
		lpCriticalSection->RecursionCount = 1;
		return TRUE;
	}

	if (owningThreadId(lpCriticalSection) == threadId) {
		kernel32::InterlockedIncrement(lockCount);
		lpCriticalSection->RecursionCount++;
		return TRUE;
	}
	return FALSE;
}

void WINAPI EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("EnterCriticalSection(%p)\n", lpCriticalSection);
	if (!lpCriticalSection) {
		setLastError(ERROR_INVALID_PARAMETER);
		return;
	}

	const DWORD threadId = GetCurrentThreadId();
	if (trySpinAcquireCriticalSection(lpCriticalSection, threadId)) {
		return;
	}

	auto *lockCount = const_cast<LONG volatile *>(&lpCriticalSection->LockCount);
	LONG result = kernel32::InterlockedIncrement(lockCount);
	if (result) {
		if (owningThreadId(lpCriticalSection) == threadId) {
			lpCriticalSection->RecursionCount++;
			return;
		}
		waitForCriticalSection(lpCriticalSection);
	}
	setOwningThread(lpCriticalSection, threadId);
	lpCriticalSection->RecursionCount = 1;
}

void WINAPI LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("LeaveCriticalSection(%p)\n", lpCriticalSection);
	if (!lpCriticalSection) {
		setLastError(ERROR_INVALID_PARAMETER);
		return;
	}

	const DWORD threadId = GetCurrentThreadId();
	if (owningThreadId(lpCriticalSection) != threadId || lpCriticalSection->RecursionCount <= 0) {
		DEBUG_LOG("LeaveCriticalSection: thread %u does not own %p (owner=%u, recursion=%ld)\n", threadId,
				  lpCriticalSection, owningThreadId(lpCriticalSection),
				  static_cast<long>(lpCriticalSection->RecursionCount));
		return;
	}

	auto *lockCount = const_cast<LONG volatile *>(&lpCriticalSection->LockCount);
	if (--lpCriticalSection->RecursionCount > 0) {
		kernel32::InterlockedDecrement(lockCount);
		return;
	}

	setOwningThread(lpCriticalSection, 0);
	LONG newValue = kernel32::InterlockedDecrement(lockCount);
	if (newValue >= 0) {
		signalCriticalSection(lpCriticalSection);
	}
}

BOOL WINAPI InitOnceBeginInitialize(LPINIT_ONCE lpInitOnce, DWORD dwFlags, PBOOL fPending, GUEST_PTR *lpContext) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("InitOnceBeginInitialize(%p, %u, %p, %p)\n", lpInitOnce, dwFlags, fPending, lpContext);
	if (!lpInitOnce) {
		DEBUG_LOG("-> ERROR_INVALID_PARAMETER\n");
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	if (dwFlags & ~(INIT_ONCE_CHECK_ONLY | INIT_ONCE_ASYNC)) {
		DEBUG_LOG("-> ERROR_INVALID_PARAMETER\n");
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	auto *state = &lpInitOnce->Ptr;

	if (dwFlags & INIT_ONCE_CHECK_ONLY) {
		if (dwFlags & INIT_ONCE_ASYNC) {
			DEBUG_LOG("-> ERROR_INVALID_PARAMETER\n");
			setLastError(ERROR_INVALID_PARAMETER);
			return FALSE;
		}
		GUEST_PTR val = __atomic_load_n(state, __ATOMIC_ACQUIRE);
		if ((val & kInitOnceStateMask) != kInitOnceCompletedFlag) {
			if (fPending) {
				*fPending = TRUE;
			}
			DEBUG_LOG("-> ERROR_GEN_FAILURE\n");
			setLastError(ERROR_GEN_FAILURE);
			return FALSE;
		}
		if (fPending) {
			*fPending = FALSE;
		}
		if (lpContext) {
			*lpContext = val & ~kInitOnceStateMask;
		}
		return TRUE;
	}

	while (true) {
		GUEST_PTR val = __atomic_load_n(state, __ATOMIC_ACQUIRE);
		switch (val & kInitOnceStateMask) {
		case 0: { // first time
			if (dwFlags & INIT_ONCE_ASYNC) {
				GUEST_PTR expected = 0;
				if (__atomic_compare_exchange_n(state, &expected, static_cast<GUEST_PTR>(3), false, __ATOMIC_ACQ_REL,
												__ATOMIC_ACQUIRE)) {
					if (fPending) {
						*fPending = TRUE;
					}
					return TRUE;
				}
			} else {
				auto syncState = std::make_shared<InitOnceState>();
				GUEST_PTR expected = 0;
				if (__atomic_compare_exchange_n(state, &expected, static_cast<GUEST_PTR>(1), false, __ATOMIC_ACQ_REL,
												__ATOMIC_ACQUIRE)) {
					insertInitOnceState(lpInitOnce, syncState);
					if (fPending) {
						*fPending = TRUE;
					}
					return TRUE;
				}
			}
			break;
		}
		case 1: { // synchronous initialization in progress
			if (dwFlags & INIT_ONCE_ASYNC) {
				DEBUG_LOG("-> ERROR_INVALID_PARAMETER\n");
				setLastError(ERROR_INVALID_PARAMETER);
				return FALSE;
			}
			auto syncState = getInitOnceState(lpInitOnce);
			if (!syncState) {
				continue;
			}
			std::unique_lock lk(syncState->mutex);
			while (!syncState->completed) {
				syncState->cv.wait(lk);
			}
			if (!syncState->success) {
				lk.unlock();
				continue;
			}
			GUEST_PTR ctx = syncState->context;
			lk.unlock();
			if (fPending) {
				*fPending = FALSE;
			}
			if (lpContext) {
				*lpContext = ctx;
			}
			return TRUE;
		}
		case kInitOnceCompletedFlag: {
			if (fPending) {
				*fPending = FALSE;
			}
			if (lpContext) {
				*lpContext = val & ~kInitOnceStateMask;
			}
			return TRUE;
		}
		case 3: { // async pending
			if (!(dwFlags & INIT_ONCE_ASYNC)) {
				DEBUG_LOG("-> ERROR_INVALID_PARAMETER\n");
				setLastError(ERROR_INVALID_PARAMETER);
				return FALSE;
			}
			if (fPending) {
				*fPending = TRUE;
			}
			return TRUE;
		}
		default:
			break;
		}
	}
}

BOOL WINAPI InitOnceComplete(LPINIT_ONCE lpInitOnce, DWORD dwFlags, LPVOID lpContext) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("InitOnceComplete(%p, %u, %p)\n", lpInitOnce, dwFlags, lpContext);
	if (!lpInitOnce) {
		DEBUG_LOG("-> ERROR_INVALID_PARAMETER\n");
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	if (dwFlags & ~(INIT_ONCE_ASYNC | INIT_ONCE_INIT_FAILED)) {
		DEBUG_LOG("-> ERROR_INVALID_PARAMETER\n");
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	const bool markFailed = (dwFlags & INIT_ONCE_INIT_FAILED) != 0;
	if (markFailed) {
		if (lpContext) {
			DEBUG_LOG("-> ERROR_INVALID_PARAMETER\n");
			setLastError(ERROR_INVALID_PARAMETER);
			return FALSE;
		}
		if (dwFlags & INIT_ONCE_ASYNC) {
			DEBUG_LOG("-> ERROR_INVALID_PARAMETER\n");
			setLastError(ERROR_INVALID_PARAMETER);
			return FALSE;
		}
	}

	const GUEST_PTR contextValue = static_cast<GUEST_PTR>(reinterpret_cast<uintptr_t>(lpContext));
	if (!markFailed && (contextValue & kInitOnceReservedMask)) {
		DEBUG_LOG("-> ERROR_INVALID_PARAMETER\n");
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	auto *state = &lpInitOnce->Ptr;
	const GUEST_PTR finalValue = markFailed ? 0 : (contextValue | kInitOnceCompletedFlag);

	while (true) {
		GUEST_PTR val = __atomic_load_n(state, __ATOMIC_ACQUIRE);
		switch (val & kInitOnceStateMask) {
		case 1: {
			auto syncState = getInitOnceState(lpInitOnce);
			if (!syncState) {
				DEBUG_LOG("-> ERROR_GEN_FAILURE\n");
				setLastError(ERROR_GEN_FAILURE);
				return FALSE;
			}
			if (!__atomic_compare_exchange_n(state, &val, finalValue, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
				continue;
			}
			{
				std::lock_guard lk(syncState->mutex);
				syncState->completed = true;
				syncState->success = !markFailed;
				syncState->context = markFailed ? GUEST_NULL : contextValue;
			}
			syncState->cv.notify_all();
			eraseInitOnceState(lpInitOnce);
			return TRUE;
		}
		case 3:
			if (!(dwFlags & INIT_ONCE_ASYNC)) {
				DEBUG_LOG("-> ERROR_INVALID_PARAMETER\n");
				setLastError(ERROR_INVALID_PARAMETER);
				return FALSE;
			}
			if (!__atomic_compare_exchange_n(state, &val, finalValue, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
				continue;
			}
			return TRUE;
		default:
			DEBUG_LOG("-> ERROR_GEN_FAILURE\n");
			setLastError(ERROR_GEN_FAILURE);
			return FALSE;
		}
	}
}

void WINAPI AcquireSRWLockShared(PSRWLOCK SRWLock) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("AcquireSRWLockShared(%p)\n", SRWLock);
	if (!SRWLock) {
		return;
	}
	auto *value = &SRWLock->Value;
	while (true) {
		ULONG current = __atomic_load_n(value, __ATOMIC_ACQUIRE);
		if (current & kSrwLockExclusive) {
			ULONG observed = current;
			kernel32::WaitOnAddress(reinterpret_cast<VOID volatile *>(value), &observed, sizeof(observed), INFINITE);
			continue;
		}
		ULONG desired = current + kSrwLockSharedIncrement;
		if (__atomic_compare_exchange_n(value, &current, desired, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
			return;
		}
	}
}

void WINAPI ReleaseSRWLockShared(PSRWLOCK SRWLock) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("ReleaseSRWLockShared(%p)\n", SRWLock);
	if (!SRWLock) {
		return;
	}
	auto *value = &SRWLock->Value;
	ULONG previous = __atomic_fetch_sub(value, kSrwLockSharedIncrement, __ATOMIC_ACQ_REL);
	ULONG newValue = previous - kSrwLockSharedIncrement;
	if (newValue == 0) {
		kernel32::WakeByAddressAll(value);
	}
}

void WINAPI AcquireSRWLockExclusive(PSRWLOCK SRWLock) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("AcquireSRWLockExclusive(%p)\n", SRWLock);
	if (!SRWLock) {
		return;
	}
	auto *value = &SRWLock->Value;
	while (true) {
		ULONG expected = 0;
		if (__atomic_compare_exchange_n(value, &expected, kSrwLockExclusive, false, __ATOMIC_ACQ_REL,
										__ATOMIC_ACQUIRE)) {
			return;
		}
		kernel32::WaitOnAddress(reinterpret_cast<VOID volatile *>(value), &expected, sizeof(expected), INFINITE);
	}
}

void WINAPI ReleaseSRWLockExclusive(PSRWLOCK SRWLock) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("ReleaseSRWLockExclusive(%p)\n", SRWLock);
	if (!SRWLock) {
		return;
	}
	__atomic_store_n(&SRWLock->Value, 0u, __ATOMIC_RELEASE);
	kernel32::WakeByAddressAll(&SRWLock->Value);
}

BOOLEAN WINAPI TryAcquireSRWLockExclusive(PSRWLOCK SRWLock) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("TryAcquireSRWLockExclusive(%p)\n", SRWLock);
	if (!SRWLock) {
		return FALSE;
	}
	ULONG expected = 0;
	if (__atomic_compare_exchange_n(&SRWLock->Value, &expected, kSrwLockExclusive, false, __ATOMIC_ACQ_REL,
									__ATOMIC_ACQUIRE)) {
		return TRUE;
	}
	return FALSE;
}

BOOLEAN WINAPI TryAcquireSRWLockShared(PSRWLOCK SRWLock) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("TryAcquireSRWLockShared(%p)\n", SRWLock);
	if (!SRWLock) {
		return FALSE;
	}
	ULONG current = __atomic_load_n(&SRWLock->Value, __ATOMIC_ACQUIRE);
	while (!(current & kSrwLockExclusive)) {
		ULONG desired = current + kSrwLockSharedIncrement;
		if (__atomic_compare_exchange_n(&SRWLock->Value, &current, desired, true, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
			return TRUE;
		}
	}
	return FALSE;
}

} // namespace kernel32
