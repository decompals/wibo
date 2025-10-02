#pragma once

#include "common.h"

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

LONG WIN_FUNC InterlockedIncrement(LONG volatile *Addend);
LONG WIN_FUNC InterlockedDecrement(LONG volatile *Addend);
LONG WIN_FUNC InterlockedExchange(LONG volatile *Target, LONG Value);
LONG WIN_FUNC InterlockedCompareExchange(LONG volatile *Destination, LONG Exchange, LONG Comperand);
void WIN_FUNC InitializeSListHead(PSLIST_HEADER ListHead);

} // namespace kernel32
