#include "interlockedapi.h"

#include "common.h"
#include "context.h"

#include <cstring>

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

} // namespace kernel32
