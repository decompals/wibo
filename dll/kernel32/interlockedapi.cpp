#include "interlockedapi.h"

#include "common.h"
#include "context.h"

#include <atomic>
#include <cstring>

namespace kernel32 {

LONG WIN_FUNC InterlockedIncrement(LONG volatile *Addend) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("InterlockedIncrement(%p)\n", Addend);
	std::atomic_ref<LONG> a(*const_cast<LONG *>(Addend));
	return a.fetch_add(1, std::memory_order_seq_cst) + 1;
}

LONG WIN_FUNC InterlockedDecrement(LONG volatile *Addend) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("InterlockedDecrement(%p)\n", Addend);
	std::atomic_ref<LONG> a(*const_cast<LONG *>(Addend));
	return a.fetch_sub(1, std::memory_order_seq_cst) - 1;
}

LONG WIN_FUNC InterlockedExchange(LONG volatile *Target, LONG Value) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("InterlockedExchange(%p, %ld)\n", Target, static_cast<long>(Value));
	std::atomic_ref<LONG> a(*const_cast<LONG *>(Target));
	return a.exchange(Value, std::memory_order_seq_cst);
}

LONG WIN_FUNC InterlockedCompareExchange(LONG volatile *Destination, LONG Exchange, LONG Comperand) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("InterlockedCompareExchange(%p, %ld, %ld)\n", Destination, static_cast<long>(Exchange),
				static_cast<long>(Comperand));

	std::atomic_ref<LONG> a(*const_cast<LONG *>(Destination));
	LONG expected = Comperand;
	a.compare_exchange_strong(expected, Exchange, std::memory_order_seq_cst);
	return expected;
}

void WIN_FUNC InitializeSListHead(PSLIST_HEADER ListHead) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("InitializeSListHead(%p)\n", ListHead);
	if (!ListHead) {
		return;
	}
	std::memset(ListHead, 0, sizeof(*ListHead));
}

} // namespace kernel32
