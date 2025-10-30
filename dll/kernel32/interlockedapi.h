#pragma once

#include "types.h"

namespace kernel32 {

struct SLIST_ENTRY {
	SLIST_ENTRY *Next;
};

using PSLIST_ENTRY = SLIST_ENTRY *;

struct SLIST_HEADER {
	SLIST_ENTRY *Head;
	unsigned short Depth;
	unsigned short Sequence;
};

using PSLIST_HEADER = SLIST_HEADER *;

LONG WINAPI InterlockedIncrement(LONG volatile *Addend);
LONG WINAPI InterlockedDecrement(LONG volatile *Addend);
LONG WINAPI InterlockedExchange(LONG volatile *Target, LONG Value);
LONG WINAPI InterlockedCompareExchange(LONG volatile *Destination, LONG Exchange, LONG Comperand);
void WINAPI InitializeSListHead(PSLIST_HEADER ListHead);

} // namespace kernel32
