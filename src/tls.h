#pragma once

#include "common.h"

namespace wibo::tls {

constexpr DWORD kInvalidTlsIndex = 0xFFFFFFFFu;
constexpr size_t kTlsMaxSlotCount = 1088;

void initializeTib(TIB *tib);
void cleanupTib(TIB *tib);

void forEachTib(void (*callback)(TIB *, void *), void *context);

bool ensureModulePointerCapacity(size_t capacity);
bool setModulePointer(TIB *tib, size_t index, void *value);
void clearModulePointer(TIB *tib, size_t index);

DWORD reserveSlot();
bool releaseSlot(DWORD index);
bool isSlotAllocated(DWORD index);

void *getValue(TIB *tib, DWORD index);
bool setValue(TIB *tib, DWORD index, void *value);

void *getValue(DWORD index);
bool setValue(DWORD index, void *value);

} // namespace wibo::tls
