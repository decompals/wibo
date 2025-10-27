#include "tls.h"

#include <algorithm>
#include <array>
#include <mutex>

namespace {

std::array<bool, kTlsSlotCount> g_slotUsed{};
std::mutex g_slotMutex;

} // namespace

namespace wibo::tls {

void initializeTib(TIB *tib) {
	if (!tib) {
		return;
	}
	std::fill(std::begin(tib->tlsSlots), std::end(tib->tlsSlots), nullptr);
	tib->tlsLinks.flink = nullptr;
	tib->tlsLinks.blink = nullptr;
	tib->tlsExpansionSlots = nullptr;
	tib->flsSlots = nullptr;
}

DWORD reserveSlot() {
	std::lock_guard lock(g_slotMutex);
	for (DWORD index = 0; index < static_cast<DWORD>(kTlsSlotCount); ++index) {
		if (!g_slotUsed[index]) {
			g_slotUsed[index] = true;
			return index;
		}
	}
	return kInvalidTlsIndex;
}

bool releaseSlot(DWORD index) {
	if (index >= static_cast<DWORD>(kTlsSlotCount)) {
		return false;
	}
	std::lock_guard lock(g_slotMutex);
	if (!g_slotUsed[index]) {
		return false;
	}
	g_slotUsed[index] = false;
	return true;
}

bool isSlotAllocated(DWORD index) {
	std::lock_guard lock(g_slotMutex);
	return index < kTlsSlotCount && g_slotUsed[index];
}

void *getValue(TIB *tib, DWORD index) {
	if (!tib || index >= static_cast<DWORD>(kTlsSlotCount)) {
		return nullptr;
	}
	return tib->tlsSlots[index];
}

bool setValue(TIB *tib, DWORD index, void *value) {
	if (!tib || index >= static_cast<DWORD>(kTlsSlotCount)) {
		return false;
	}
	tib->tlsSlots[index] = value;
	return true;
}

void *getValue(DWORD index) { return getValue(getThreadTibForHost(), index); }

bool setValue(DWORD index, void *value) { return setValue(getThreadTibForHost(), index, value); }

} // namespace wibo::tls
