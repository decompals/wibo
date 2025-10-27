#include "tls.h"
#include "common.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdlib>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace {

constexpr size_t kMaxExpansionSlots = wibo::tls::kTlsMaxSlotCount - kTlsSlotCount;

std::mutex g_tlsMutex;
std::array<bool, wibo::tls::kTlsMaxSlotCount> g_slotUsed{};
std::vector<TIB *> g_activeTibs;
size_t g_expansionCapacity = 0;

struct TlsArray {
	size_t capacity;
	void *slots[];
};

std::unordered_map<TIB *, TlsArray *> g_moduleArrays;
std::unordered_map<TIB *, std::vector<TlsArray *>> g_moduleGarbage;
size_t g_moduleArrayCapacity = 0;

TlsArray *allocateTlsArray(size_t capacity) {
	if (capacity == 0 || capacity > kMaxExpansionSlots) {
		return nullptr;
	}
	const size_t bytes = sizeof(TlsArray) + capacity * sizeof(void *);
	auto *arr = static_cast<TlsArray *>(std::calloc(1, bytes));
	if (!arr) {
		return nullptr;
	}
	arr->capacity = capacity;
	return arr;
}

inline TlsArray *arrayFromSlots(void *slots) {
	return slots ? reinterpret_cast<TlsArray *>(reinterpret_cast<uint8_t *>(slots) - offsetof(TlsArray, slots))
				 : nullptr;
}

TlsArray *getExpansionArray(TIB *tib) {
	if (!tib) {
		return nullptr;
	}
	return arrayFromSlots(tib->tlsExpansionSlots);
}

void setExpansionArray(TIB *tib, TlsArray *arr) {
	if (!tib) {
		return;
	}
	tib->tlsExpansionSlots = arr ? arr->slots : nullptr;
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
	TlsArray *oldArr;
	TlsArray *newArr;
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
		auto *currArr = getExpansionArray(tib);
		size_t currentCapacity = currArr ? currArr->capacity : 0;
		if (currentCapacity >= target) {
			continue;
		}
		auto *newArr = allocateTlsArray(target);
		if (!newArr) {
			for (auto &entry : pending) {
				std::free(entry.newArr);
			}
			return false;
		}
		if (currArr) {
			std::copy_n(currArr->slots, std::min(currArr->capacity, newArr->capacity), newArr->slots);
		}
		pending.emplace_back(tib, currArr, newArr);
	}
	for (auto &entry : pending) {
		setExpansionArray(entry.tib, entry.newArr);
	}
	for (auto &entry : pending) {
		if (entry.oldArr) {
			std::free(entry.oldArr);
		}
	}
	g_expansionCapacity = target;
	return true;
}

TlsArray *getModuleArray(TIB *tib) {
	if (!tib) {
		return nullptr;
	}
	auto it = g_moduleArrays.find(tib);
	if (it != g_moduleArrays.end()) {
		return it->second;
	}
	auto *array = arrayFromSlots(tib->threadLocalStoragePointer);
	if (array) {
		g_moduleArrays.emplace(tib, array);
	}
	return array;
}

void queueOldModuleArray(TIB *tib, TlsArray *array) {
	if (!tib || !array) {
		return;
	}
	g_moduleGarbage[tib].push_back(array);
}

struct ModulePendingResize {
	TIB *tib;
	TlsArray *oldArray;
	TlsArray *newArray;
};

bool ensureModuleArrayCapacityLocked(size_t required) {
	if (required == 0) {
		return true;
	}
	if (required <= g_moduleArrayCapacity) {
		return true;
	}
	size_t target = g_moduleArrayCapacity ? g_moduleArrayCapacity : static_cast<size_t>(1);
	while (target < required) {
		size_t next = target * 2;
		if (next <= target) {
			target = required;
			break;
		}
		target = std::max(next, required);
	}
	std::vector<ModulePendingResize> pending;
	pending.reserve(g_activeTibs.size());
	for (TIB *tib : g_activeTibs) {
		auto *current = getModuleArray(tib);
		size_t currentCapacity = current ? current->capacity : 0;
		if (currentCapacity >= target) {
			continue;
		}
		auto *newArray = allocateTlsArray(target);
		if (!newArray) {
			for (auto &entry : pending) {
				std::free(entry.newArray);
			}
			return false;
		}
		if (current) {
			std::copy_n(current->slots, std::min(current->capacity, newArray->capacity), newArray->slots);
		}
		pending.emplace_back(tib, current, newArray);
	}
	for (auto &entry : pending) {
		g_moduleArrays[entry.tib] = entry.newArray;
		entry.tib->threadLocalStoragePointer = entry.newArray->slots;
		if (entry.oldArray) {
			queueOldModuleArray(entry.tib, entry.oldArray);
		}
	}
	g_moduleArrayCapacity = target;
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
		auto *arr = getExpansionArray(tib);
		if (!arr || expansionIndex >= arr->capacity) {
			continue;
		}
		arr->slots[expansionIndex] = nullptr;
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
	if (g_expansionCapacity > 0 && !getExpansionArray(tib)) {
		if (auto *arr = allocateTlsArray(g_expansionCapacity)) {
			setExpansionArray(tib, arr);
		}
	}
	if (g_moduleArrayCapacity > 0) {
		if (!ensureModuleArrayCapacityLocked(g_moduleArrayCapacity)) {
			DEBUG_LOG("initializeTib: failed to allocate module TLS array for %p\n", tib);
		}
	}
}

void cleanupTib(TIB *tib) {
	if (!tib) {
		return;
	}
	std::lock_guard lock(g_tlsMutex);
	if (auto *arr = getExpansionArray(tib)) {
		std::free(arr);
		setExpansionArray(tib, nullptr);
	}
	if (auto *arr = getModuleArray(tib)) {
		g_moduleArrays.erase(tib);
		std::free(arr);
	}
	if (auto garbageIt = g_moduleGarbage.find(tib); garbageIt != g_moduleGarbage.end()) {
		for (auto *oldArray : garbageIt->second) {
			std::free(oldArray);
		}
		g_moduleGarbage.erase(garbageIt);
	}
	tib->threadLocalStoragePointer = nullptr;
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
	auto *arr = getExpansionArray(tib);
	if (!arr) {
		return nullptr;
	}
	size_t expansionIndex = static_cast<size_t>(index) - kTlsSlotCount;
	if (expansionIndex >= arr->capacity) {
		return nullptr;
	}
	return arr->slots[expansionIndex];
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
	auto *arr = getExpansionArray(tib);
	if ((!arr || expansionIndex >= arr->capacity) && !ensureGlobalExpansionCapacityLocked(expansionIndex + 1)) {
		return false;
	}
	arr = getExpansionArray(tib);
	if (!arr || expansionIndex >= arr->capacity) {
		return false;
	}
	arr->slots[expansionIndex] = value;
	return true;
}

void *getValue(DWORD index) { return getValue(getThreadTibForHost(), index); }

bool setValue(DWORD index, void *value) { return setValue(getThreadTibForHost(), index, value); }

void forEachTib(void (*callback)(TIB *, void *), void *context) {
	if (!callback) {
		return;
	}
	std::vector<TIB *> tibs;
	{
		std::lock_guard lock(g_tlsMutex);
		tibs = g_activeTibs;
	}
	for (TIB *tib : tibs) {
		callback(tib, context);
	}
}

bool ensureModulePointerCapacity(size_t capacity) {
	std::lock_guard lock(g_tlsMutex);
	return ensureModuleArrayCapacityLocked(capacity);
}

bool setModulePointer(TIB *tib, size_t index, void *value) {
	if (!tib) {
		return false;
	}
	std::lock_guard lock(g_tlsMutex);
	if (!ensureModuleArrayCapacityLocked(index + 1)) {
		return false;
	}
	auto *array = getModuleArray(tib);
	if (!array || index >= array->capacity) {
		return false;
	}
	array->slots[index] = value;
	tib->threadLocalStoragePointer = array->slots;
	return true;
}

void clearModulePointer(TIB *tib, size_t index) {
	if (!tib) {
		return;
	}
	std::lock_guard lock(g_tlsMutex);
	auto *array = getModuleArray(tib);
	if (!array || index >= array->capacity) {
		return;
	}
	array->slots[index] = nullptr;
}

} // namespace wibo::tls
