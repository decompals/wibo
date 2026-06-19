#include "interlockedapi.h"

#include "common.h"
#include "context.h"

#include <cstring>
#include <mutex>

namespace kernel32 {

LONG WINAPI InterlockedIncrement(LONG volatile *Addend) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("InterlockedIncrement(%p)\n", Addend);
	auto *ptr = const_cast<LONG *>(Addend);
	return __atomic_add_fetch(ptr, 1, __ATOMIC_SEQ_CST);
}

LONG WINAPI InterlockedDecrement(LONG volatile *Addend) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("InterlockedDecrement(%p)\n", Addend);
	auto *ptr = const_cast<LONG *>(Addend);
	return __atomic_sub_fetch(ptr, 1, __ATOMIC_SEQ_CST);
}

LONG WINAPI InterlockedExchange(LONG volatile *Target, LONG Value) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("InterlockedExchange(%p, %ld)\n", Target, static_cast<long>(Value));
	auto *ptr = const_cast<LONG *>(Target);
	return __atomic_exchange_n(ptr, Value, __ATOMIC_SEQ_CST);
}

LONG WINAPI InterlockedCompareExchange(LONG volatile *Destination, LONG Exchange, LONG Comperand) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("InterlockedCompareExchange(%p, %ld, %ld)\n", Destination, static_cast<long>(Exchange),
				static_cast<long>(Comperand));

	auto *ptr = const_cast<LONG *>(Destination);
	LONG expected = Comperand;
	__atomic_compare_exchange_n(ptr, &expected, Exchange, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
	return expected;
}

void WINAPI InitializeSListHead(PSLIST_HEADER ListHead) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("InitializeSListHead(%p)\n", ListHead);
	if (!ListHead) {
		return;
	}
	std::memset(ListHead, 0, sizeof(*ListHead));
}

// These are "Interlocked" ops on a shared list; mspdbcore's worker-thread pool
// pushes/pops the same SLIST concurrently, so they MUST be atomic. A global
// mutex serializes all SLIST operations (correct, if not strictly lock-free).
static std::mutex g_slistMutex;

PSLIST_ENTRY WINAPI InterlockedPushEntrySList(PSLIST_HEADER ListHead, PSLIST_ENTRY ListEntry) {
	HOST_CONTEXT_GUARD();
	if (!ListHead || !ListEntry) return nullptr;
	std::lock_guard<std::mutex> lk(g_slistMutex);
	GUEST_PTR prevHead = ListHead->Head;
	ListEntry->Next = prevHead;
	ListHead->Head = toGuestPtr(ListEntry);
	ListHead->Depth++;
	return fromGuestPtr<SLIST_ENTRY>(prevHead);
}

PSLIST_ENTRY WINAPI InterlockedPopEntrySList(PSLIST_HEADER ListHead) {
	HOST_CONTEXT_GUARD();
	if (!ListHead) return nullptr;
	std::lock_guard<std::mutex> lk(g_slistMutex);
	if (!ListHead->Head) return nullptr;
	PSLIST_ENTRY entry = fromGuestPtr<SLIST_ENTRY>(ListHead->Head);
	ListHead->Head = entry->Next;
	if (ListHead->Depth) ListHead->Depth--;
	return entry;
}

PSLIST_ENTRY WINAPI InterlockedFlushSList(PSLIST_HEADER ListHead) {
	HOST_CONTEXT_GUARD();
	if (!ListHead) return nullptr;
	std::lock_guard<std::mutex> lk(g_slistMutex);
	PSLIST_ENTRY first = fromGuestPtr<SLIST_ENTRY>(ListHead->Head);
	ListHead->Head = GUEST_NULL;
	ListHead->Depth = 0;
	return first;
}

USHORT WINAPI QueryDepthSList(PSLIST_HEADER ListHead) {
	HOST_CONTEXT_GUARD();
	if (!ListHead) return 0;
	std::lock_guard<std::mutex> lk(g_slistMutex);
	return ListHead->Depth;
}

} // namespace kernel32
