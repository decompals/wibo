#include "interlockedapi.h"
#include "common.h"

#include <cstring>

namespace kernel32 {

LONG WIN_FUNC InterlockedIncrement(LONG volatile *Addend) {
	VERBOSE_LOG("InterlockedIncrement(%p)\n", Addend);
	return ++(*Addend);
}

LONG WIN_FUNC InterlockedDecrement(LONG volatile *Addend) {
	VERBOSE_LOG("InterlockedDecrement(%p)\n", Addend);
	return --(*Addend);
}

LONG WIN_FUNC InterlockedExchange(LONG volatile *Target, LONG Value) {
	VERBOSE_LOG("InterlockedExchange(%p, %ld)\n", Target, static_cast<long>(Value));
	LONG initial = *Target;
	*Target = Value;
	return initial;
}

LONG WIN_FUNC InterlockedCompareExchange(LONG volatile *Destination, LONG Exchange, LONG Comperand) {
	VERBOSE_LOG("InterlockedCompareExchange(%p, %ld, %ld)\n", Destination, static_cast<long>(Exchange),
				static_cast<long>(Comperand));
	LONG original = *Destination;
	if (original == Comperand) {
		*Destination = Exchange;
	}
	return original;
}

void WIN_FUNC InitializeSListHead(PSLIST_HEADER ListHead) {
	DEBUG_LOG("InitializeSListHead(%p)\n", ListHead);
	if (!ListHead) {
		return;
	}
	std::memset(ListHead, 0, sizeof(*ListHead));
}

} // namespace kernel32
