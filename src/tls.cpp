#include "tls.h"
#include "common.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdlib>
#include <mutex>
#include <vector>

namespace {

constexpr size_t kMaxExpansionSlots = wibo::tls::kTlsMaxSlotCount - kTlsSlotCount;

std::mutex g_tlsMutex;
std::array<bool, wibo::tls::kTlsMaxSlotCount> g_slotUsed{};
std::vector<TIB *> g_activeTibs;
size_t g_expansionCapacity = 0;

struct TlsVector {
	size_t capacity;
	void *slots[];
};

TlsVector *allocateVector(size_t capacity) {
	if (capacity == 0 || capacity > kMaxExpansionSlots) {
		return nullptr;
	}
	const size_t bytes = sizeof(TlsVector) + capacity * sizeof(void *);
	auto *vector = static_cast<TlsVector *>(std::calloc(1, bytes));
	if (!vector) {
		return nullptr;
	}
	vector->capacity = capacity;
	return vector;
}

TlsVector *vectorFromSlots(void **slots) {
	if (!slots) {
		return nullptr;
	}
	auto *base = reinterpret_cast<unsigned char *>(slots) - offsetof(TlsVector, slots);
	return reinterpret_cast<TlsVector *>(base);
}

TlsVector *getExpansionVector(TIB *tib) {
	if (!tib) {
		return nullptr;
	}
	return vectorFromSlots(tib->tlsExpansionSlots);
}

void setExpansionVector(TIB *tib, TlsVector *vector) {
	if (!tib) {
		return;
	}
	tib->tlsExpansionSlots = vector ? vector->slots : nullptr;
}

size_t chooseCapacity(size_t current, size_t required) {
	if (required == 0) {
		return current;
	}
	if (required > kMaxExpansionSlots) {
		return 0;
	}
	size_t capacity = current;
	if (capacity == 0) {
		capacity = 1;
	}
	while (capacity < required) {
		size_t next = capacity * 2;
		if (next <= capacity || next > kMaxExpansionSlots) {
			capacity = kMaxExpansionSlots;
		} else {
			capacity = next;
		}
	}
	if (capacity > kMaxExpansionSlots) {
		capacity = kMaxExpansionSlots;
	}
	if (capacity < required) {
		return 0;
	}
	return capacity;
}

struct PendingResize {
	TIB *tib;
	TlsVector *oldVector;
	TlsVector *newVector;
};

bool ensureGlobalExpansionCapacityLocked(size_t required) {
	if (required == 0) {
		return true;
	}
	if (required <= g_expansionCapacity) {
		return true;
	}
	size_t target = chooseCapacity(g_expansionCapacity, required);
	if (target == 0) {
		return false;
	}
	std::vector<PendingResize> pending;
	pending.reserve(g_activeTibs.size());
	for (TIB *tib : g_activeTibs) {
		TlsVector *currentVector = getExpansionVector(tib);
		size_t currentCapacity = currentVector ? currentVector->capacity : 0;
		if (currentCapacity >= target) {
			continue;
		}
		TlsVector *newVector = allocateVector(target);
		if (!newVector) {
			for (auto &entry : pending) {
				std::free(entry.newVector);
			}
			return false;
		}
		if (currentVector) {
			std::copy_n(currentVector->slots, std::min(currentVector->capacity, newVector->capacity), newVector->slots);
		}
		pending.emplace_back(tib, currentVector, newVector);
	}
	for (auto &entry : pending) {
		setExpansionVector(entry.tib, entry.newVector);
	}
	for (auto &entry : pending) {
		if (entry.oldVector) {
			std::free(entry.oldVector);
		}
	}
	g_expansionCapacity = target;
	return true;
}

void zeroSlotForAllTibs(size_t index) {
	if (index < kTlsSlotCount) {
		for (TIB *tib : g_activeTibs) {
			tib->tlsSlots[index] = nullptr;
		}
		return;
	}
	size_t expansionIndex = index - kTlsSlotCount;
	for (TIB *tib : g_activeTibs) {
		TlsVector *vector = getExpansionVector(tib);
		if (!vector || expansionIndex >= vector->capacity) {
			continue;
		}
		vector->slots[expansionIndex] = nullptr;
	}
}

} // namespace

namespace wibo::tls {

void initializeTib(TIB *tib) {
	if (!tib) {
		return;
	}
	std::lock_guard lock(g_tlsMutex);
	if (std::find(g_activeTibs.begin(), g_activeTibs.end(), tib) != g_activeTibs.end()) {
		return;
	}
	g_activeTibs.push_back(tib);
	if (g_expansionCapacity > 0 && !getExpansionVector(tib)) {
		if (TlsVector *vector = allocateVector(g_expansionCapacity)) {
			setExpansionVector(tib, vector);
		}
	}
}

void cleanupTib(TIB *tib) {
	if (!tib) {
		return;
	}
	std::lock_guard lock(g_tlsMutex);
	if (TlsVector *vector = getExpansionVector(tib)) {
		std::free(vector);
		setExpansionVector(tib, nullptr);
	}
	auto it = std::find(g_activeTibs.begin(), g_activeTibs.end(), tib);
	if (it != g_activeTibs.end()) {
		g_activeTibs.erase(it);
	}
}

DWORD reserveSlot() {
	std::lock_guard lock(g_tlsMutex);
	for (DWORD index = 0; index < static_cast<DWORD>(wibo::tls::kTlsMaxSlotCount); ++index) {
		if (g_slotUsed[index]) {
			continue;
		}
		if (index >= static_cast<DWORD>(kTlsSlotCount)) {
			size_t required = static_cast<size_t>(index) - kTlsSlotCount + 1;
			if (!ensureGlobalExpansionCapacityLocked(required)) {
				return kInvalidTlsIndex;
			}
		}
		g_slotUsed[index] = true;
		zeroSlotForAllTibs(index);
		return index;
	}
	return kInvalidTlsIndex;
}

bool releaseSlot(DWORD index) {
	if (index >= static_cast<DWORD>(wibo::tls::kTlsMaxSlotCount)) {
		return false;
	}
	std::lock_guard lock(g_tlsMutex);
	if (!g_slotUsed[index]) {
		return false;
	}
	g_slotUsed[index] = false;
	zeroSlotForAllTibs(index);
	return true;
}

bool isSlotAllocated(DWORD index) {
	std::lock_guard lock(g_tlsMutex);
	return index < wibo::tls::kTlsMaxSlotCount && g_slotUsed[index];
}

void *getValue(TIB *tib, DWORD index) {
	if (!tib || index >= static_cast<DWORD>(wibo::tls::kTlsMaxSlotCount)) {
		return nullptr;
	}
	if (index < static_cast<DWORD>(kTlsSlotCount)) {
		return tib->tlsSlots[index];
	}
	std::lock_guard lock(g_tlsMutex);
	TlsVector *vector = getExpansionVector(tib);
	if (!vector) {
		return nullptr;
	}
	size_t expansionIndex = static_cast<size_t>(index) - kTlsSlotCount;
	if (expansionIndex >= vector->capacity) {
		return nullptr;
	}
	return vector->slots[expansionIndex];
}

bool setValue(TIB *tib, DWORD index, void *value) {
	if (!tib || index >= static_cast<DWORD>(wibo::tls::kTlsMaxSlotCount)) {
		return false;
	}
	if (index < static_cast<DWORD>(kTlsSlotCount)) {
		tib->tlsSlots[index] = value;
		return true;
	}
	std::lock_guard lock(g_tlsMutex);
	size_t expansionIndex = static_cast<size_t>(index) - kTlsSlotCount;
	TlsVector *vector = getExpansionVector(tib);
	if ((!vector || expansionIndex >= vector->capacity) && !ensureGlobalExpansionCapacityLocked(expansionIndex + 1)) {
		return false;
	}
	vector = getExpansionVector(tib);
	if (!vector || expansionIndex >= vector->capacity) {
		return false;
	}
	vector->slots[expansionIndex] = value;
	return true;
}

void *getValue(DWORD index) { return getValue(getThreadTibForHost(), index); }

bool setValue(DWORD index, void *value) { return setValue(getThreadTibForHost(), index, value); }

} // namespace wibo::tls
