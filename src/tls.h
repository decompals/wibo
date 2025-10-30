#pragma once

#include "common.h"

namespace wibo::tls {

constexpr DWORD kInvalidTlsIndex = 0xFFFFFFFFu;
constexpr size_t kTlsMaxSlotCount = 1088;

void initializeTib(TEB *tib);
void cleanupTib(TEB *tib);

void forEachTib(void (*callback)(TEB *, void *), void *context);

bool ensureModulePointerCapacity(size_t capacity);
bool setModulePointer(TEB *tib, size_t index, void *value);
void clearModulePointer(TEB *tib, size_t index);

DWORD reserveSlot();
bool releaseSlot(DWORD index);
bool isSlotAllocated(DWORD index);

void *getValue(TEB *tib, DWORD index);
bool setValue(TEB *tib, DWORD index, void *value);

void *getValue(DWORD index);
bool setValue(DWORD index, void *value);

} // namespace wibo::tls
