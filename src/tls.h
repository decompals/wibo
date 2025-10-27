#pragma once

#include "common.h"

namespace wibo::tls {

constexpr DWORD kInvalidTlsIndex = 0xFFFFFFFFu;

void initializeTib(TIB *tib);

DWORD reserveSlot();
bool releaseSlot(DWORD index);
bool isSlotAllocated(DWORD index);

void *getValue(TIB *tib, DWORD index);
bool setValue(TIB *tib, DWORD index, void *value);

void *getValue(DWORD index);
bool setValue(DWORD index, void *value);

} // namespace wibo::tls

