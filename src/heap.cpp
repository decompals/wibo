#include "heap.h"
#include "common.h"
#include "errors.h"
#include "types.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <map>
#include <mutex>
#include <utility>
#include <vector>

// Alpine hack: rename duplicate prctl_mm_map (sys/prctl.h also includes it)
#define prctl_mm_map _prctl_mm_map
#include <linux/prctl.h>
#undef prctl_mm_map

#include <mimalloc.h>
#include <mimalloc/internal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

// Pre-initialization logging macros
#define LOG_OUT(msg) write(STDOUT_FILENO, msg, strlen(msg))
#define LOG_ERR(msg) write(STDERR_FILENO, msg, strlen(msg))

namespace {

constexpr uintptr_t kLowMemoryStart = 0x00110000UL; // 1 MiB + 64 KiB
constexpr uintptr_t kTopDownStart = 0x7F000000UL;	// Just below 2GB
constexpr uintptr_t kTwoGB = 0x80000000UL;
constexpr std::size_t kGuestArenaSize = 512ULL * 1024ULL * 1024ULL; // 512 MiB
constexpr std::size_t kVirtualAllocationGranularity = 64ULL * 1024ULL;

struct ArenaRange {
	void *start = nullptr;
	std::size_t size = 0;
};

// Guest arena (<2GB)
ArenaRange g_guest;
mi_arena_id_t g_guestArenaId = nullptr;
thread_local mi_heap_t *g_guestHeap = nullptr;

bool g_initialized = false;
std::once_flag g_initOnce;

std::mutex g_mappingsMutex;
std::map<uintptr_t, MEMORY_BASIC_INFORMATION> *g_mappings = nullptr;

std::mutex g_virtualAllocMutex;

struct VirtualAllocation {
	uintptr_t base = 0;
	std::size_t size = 0;
	DWORD allocationProtect = 0;
	DWORD type = MEM_PRIVATE;
	std::vector<DWORD> pageProtect;
};

std::map<uintptr_t, VirtualAllocation> g_virtualAllocations;

const uintptr_t kDefaultMmapMinAddr = 0x10000u;

uintptr_t readMmapMinAddr() {
	char buf[64];
	int fd = open("/proc/sys/vm/mmap_min_addr", O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0) {
		return kDefaultMmapMinAddr;
	}
	ssize_t rd = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (rd <= 0) {
		return kDefaultMmapMinAddr;
	}
	uintptr_t value = 0;
	auto result = std::from_chars(buf, buf + rd, value);
	if (result.ec != std::errc()) {
		LOG_ERR("heap: failed to parse mmap_min_addr\n");
		return kDefaultMmapMinAddr;
	}
	if (value < kDefaultMmapMinAddr) {
		value = kDefaultMmapMinAddr;
	}
	return value;
}

uintptr_t mmapMinAddr() {
	static uintptr_t minAddr = readMmapMinAddr();
	return minAddr;
}

uintptr_t alignDown(uintptr_t value, std::size_t alignment) {
	const uintptr_t mask = static_cast<uintptr_t>(alignment) - 1;
	return value & ~mask;
}

uintptr_t alignUp(uintptr_t value, std::size_t alignment) {
	const uintptr_t mask = static_cast<uintptr_t>(alignment) - 1;
	if (mask == std::numeric_limits<uintptr_t>::max()) {
		return value;
	}
	if (value > std::numeric_limits<uintptr_t>::max() - mask) {
		return std::numeric_limits<uintptr_t>::max();
	}
	return (value + mask) & ~mask;
}

bool addOverflows(uintptr_t base, std::size_t amount) {
	return base > std::numeric_limits<uintptr_t>::max() - static_cast<uintptr_t>(amount);
}

uintptr_t regionEnd(const VirtualAllocation &region) { return region.base + region.size; }

std::map<uintptr_t, VirtualAllocation>::iterator findRegionIterator(uintptr_t address) {
	auto it = g_virtualAllocations.upper_bound(address);
	if (it == g_virtualAllocations.begin()) {
		return g_virtualAllocations.end();
	}
	--it;
	if (address >= regionEnd(it->second)) {
		return g_virtualAllocations.end();
	}
	return it;
}

VirtualAllocation *lookupRegion(uintptr_t address) {
	auto it = findRegionIterator(address);
	if (it == g_virtualAllocations.end()) {
		return nullptr;
	}
	return &it->second;
}

bool rangeWithinRegion(const VirtualAllocation &region, uintptr_t start, std::size_t length) {
	if (length == 0) {
		return start >= region.base && start <= regionEnd(region);
	}
	if (start < region.base) {
		return false;
	}
	if (addOverflows(start, length)) {
		return false;
	}
	return (start + length) <= regionEnd(region);
}

void markCommitted(VirtualAllocation &region, uintptr_t start, std::size_t length, DWORD protect) {
	if (length == 0) {
		return;
	}
	const std::size_t pageSize = wibo::heap::systemPageSize();
	const std::size_t firstPage = (start - region.base) / pageSize;
	const std::size_t pageCount = length / pageSize;
	for (std::size_t i = 0; i < pageCount; ++i) {
		region.pageProtect[firstPage + i] = protect;
	}
}

void markDecommitted(VirtualAllocation &region, uintptr_t start, std::size_t length) {
	if (length == 0) {
		return;
	}
	const std::size_t pageSize = wibo::heap::systemPageSize();
	const std::size_t firstPage = (start - region.base) / pageSize;
	const std::size_t pageCount = length / pageSize;
	for (std::size_t i = 0; i < pageCount; ++i) {
		region.pageProtect[firstPage + i] = 0;
	}
}

bool overlapsExistingMapping(uintptr_t base, std::size_t length) {
	if (g_mappings == nullptr || length == 0) {
		return false;
	}
	if (addOverflows(base, length - 1)) {
		return true;
	}
	uintptr_t end = base + length;
	std::lock_guard guard(g_mappingsMutex);
	auto it = g_mappings->upper_bound(base);
	if (it != g_mappings->begin()) {
		--it;
	}
	for (; it != g_mappings->end(); ++it) {
		const auto &info = it->second;
		if (info.RegionSize == 0) {
			continue;
		}
		uintptr_t mapStart = reinterpret_cast<uintptr_t>(info.BaseAddress);
		uintptr_t mapEnd = mapStart + static_cast<uintptr_t>(info.RegionSize);
		if (mapEnd <= base) {
			continue;
		}
		if (mapStart >= end) {
			break;
		}
		return true;
	}
	return false;
}

void recordGuestMapping(uintptr_t base, std::size_t size, DWORD allocationProtect, DWORD state, DWORD protect,
						DWORD type) {
	if (g_mappings == nullptr) {
		return;
	}
	MEMORY_BASIC_INFORMATION info{};
	info.BaseAddress = reinterpret_cast<void *>(base);
	info.AllocationBase = reinterpret_cast<void *>(base);
	info.AllocationProtect = allocationProtect;
	info.RegionSize = size;
	info.State = state;
	info.Protect = protect;
	info.Type = type;
	std::lock_guard guard(g_mappingsMutex);
	(*g_mappings)[base] = info;
}

void eraseGuestMapping(uintptr_t base) {
	if (g_mappings == nullptr) {
		return;
	}
	std::lock_guard guard(g_mappingsMutex);
	g_mappings->erase(base);
}

int posixProtectFromWin32(DWORD flProtect) {
	switch (flProtect & 0xFF) {
	case PAGE_NOACCESS:
		return PROT_NONE;
	case PAGE_READONLY:
		return PROT_READ;
	case PAGE_READWRITE:
	case PAGE_WRITECOPY:
		return PROT_READ | PROT_WRITE;
	case PAGE_EXECUTE:
		return PROT_EXEC;
	case PAGE_EXECUTE_READ:
		return PROT_READ | PROT_EXEC;
	case PAGE_EXECUTE_READWRITE:
	case PAGE_EXECUTE_WRITECOPY:
		return PROT_READ | PROT_WRITE | PROT_EXEC;
	default:
		DEBUG_LOG("heap: unhandled flProtect %u, defaulting to RW\n", flProtect);
		return PROT_READ | PROT_WRITE;
	}
}

wibo::heap::VmStatus vmStatusFromErrno(int err) {
	switch (err) {
	case ENOMEM:
		return wibo::heap::VmStatus::NoMemory;
	case EACCES:
	case EPERM:
		return wibo::heap::VmStatus::NoAccess;
	case EINVAL:
		return wibo::heap::VmStatus::InvalidParameter;
	case EBUSY:
		return wibo::heap::VmStatus::Rejected;
	default:
		return wibo::heap::VmStatus::UnknownError;
	}
}

void refreshGuestMapping(const VirtualAllocation &region) {
	if (g_mappings == nullptr) {
		return;
	}
	bool allCommitted = true;
	bool anyCommitted = false;
	DWORD firstProtect = 0;
	bool uniformProtect = true;
	for (DWORD pageProtect : region.pageProtect) {
		if (pageProtect == 0) {
			allCommitted = false;
			continue;
		}
		anyCommitted = true;
		if (firstProtect == 0) {
			firstProtect = pageProtect;
		} else if (firstProtect != pageProtect) {
			uniformProtect = false;
		}
	}
	DWORD state = allCommitted && anyCommitted ? MEM_COMMIT : MEM_RESERVE;
	DWORD protect = PAGE_NOACCESS;
	if (state == MEM_COMMIT) {
		if (uniformProtect && firstProtect != 0) {
			protect = firstProtect;
		} else {
			protect = PAGE_NOACCESS;
		}
	}
	DWORD allocationProtect = region.allocationProtect != 0 ? region.allocationProtect : PAGE_NOACCESS;
	recordGuestMapping(region.base, region.size, allocationProtect, state, protect, region.type);
}

bool mapAtAddr(uintptr_t addr, std::size_t size, const char *name, void **outPtr) {
	void *p = mmap(reinterpret_cast<void *>(addr), size, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (p == MAP_FAILED) {
		return false;
	}
	if (name) {
		prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, size, name);
	}
	recordGuestMapping(addr, size, PAGE_READWRITE, MEM_RESERVE, PAGE_READWRITE, MEM_PRIVATE);
	if (outPtr) {
		*outPtr = p;
	}
	return true;
}

bool findFreeMapping(std::size_t size, uintptr_t minAddr, uintptr_t maxAddr, bool preferTop, uintptr_t *outAddr) {
	if (outAddr == nullptr || size == 0 || g_mappings == nullptr) {
		return false;
	}

	const uintptr_t pageSize = wibo::heap::systemPageSize();
	const uintptr_t alignedSize = alignUp(static_cast<uintptr_t>(size), pageSize);
	const uintptr_t granularity = kVirtualAllocationGranularity;
	uintptr_t searchMin = static_cast<uintptr_t>(minAddr);
	uintptr_t searchMax = static_cast<uintptr_t>(maxAddr);

	if (searchMax <= searchMin || alignedSize > (searchMax - searchMin)) {
		return false;
	}

	std::lock_guard<std::mutex> guard(g_mappingsMutex);

	auto tryGap = [&](uintptr_t gapStart, uintptr_t gapEnd, uintptr_t &result) -> bool {
		if (gapEnd <= gapStart) {
			return false;
		}

		uintptr_t lower = alignUp(gapStart, granularity);
		if (lower >= gapEnd) {
			return false;
		}

		if (!preferTop) {
			if (lower + alignedSize <= gapEnd) {
				result = lower;
				return true;
			}
			return false;
		}

		if (gapEnd < alignedSize) {
			return false;
		}

		uintptr_t upper = gapEnd - alignedSize;
		uintptr_t chosen = alignDown(upper, granularity);
		if (chosen < lower) {
			return false;
		}
		if (chosen + alignedSize > gapEnd) {
			return false;
		}
		result = chosen;
		return true;
	};

	uintptr_t cursor = alignUp(searchMin, granularity);
	for (auto &g_mapping : *g_mappings) {
		uintptr_t mapStart = g_mapping.first;
		uintptr_t mapEnd = mapStart + static_cast<uintptr_t>(g_mapping.second.RegionSize);

		if (mapEnd <= searchMin) {
			continue;
		}
		if (mapStart >= searchMax) {
			if (tryGap(cursor, searchMax, *outAddr)) {
				return true;
			}
			break;
		}

		if (mapStart > cursor) {
			uintptr_t gapEnd = std::min(mapStart, searchMax);
			if (tryGap(cursor, gapEnd, *outAddr)) {
				return true;
			}
		}

		if (mapEnd > cursor) {
			cursor = alignUp(mapEnd, pageSize);
		}

		if (cursor >= searchMax) {
			break;
		}
	}

	if (cursor < searchMax) {
		if (tryGap(cursor, searchMax, *outAddr)) {
			return true;
		}
	}

	return false;
}

bool mapArena(std::size_t size, uintptr_t minAddr, uintptr_t maxAddr, bool preferTop, const char *name,
			  ArenaRange &out) {
	const std::size_t ps = wibo::heap::systemPageSize();
	size = (size + ps - 1) & ~(ps - 1);
	uintptr_t cand = 0;
	void *p = nullptr;
	if (findFreeMapping(size, minAddr, maxAddr, preferTop, &cand)) {
		DEBUG_LOG("heap: found free mapping at %lx\n", cand);
		if (mapAtAddr(cand, size, name, &p)) {
			out.start = p;
			out.size = size;
			return true;
		}
	}
	return false;
}

void initializeImpl() {
	if (g_initialized) {
		return;
	}

	// Map and register guest arena (below 2GB, exclusive)
	ArenaRange guest;
	if (mapArena(kGuestArenaSize, kLowMemoryStart, kTopDownStart, false, "wibo guest arena", guest)) {
		bool ok = mi_manage_os_memory_ex(guest.start, guest.size,
										 /*is_committed*/ false,
										 /*is_pinned*/ false,
										 /*is_zero*/ true,
										 /*numa_node*/ -1,
										 /*exclusive*/ true, &g_guestArenaId);
		if (ok) {
			g_guest = guest;
		} else {
			LOG_ERR("heap: failed to register guest arena with mimalloc\n");
		}
	}
	if (g_guest.size) {
		DEBUG_LOG("heap: initialized guest arena %p..%p (%zu MiB) id=%p\n", g_guest.start,
				  static_cast<void *>(static_cast<char *>(g_guest.start) + g_guest.size), g_guest.size >> 20,
				  g_guestArenaId);
	} else {
		DEBUG_LOG("heap: guest arena initialization incomplete\n");
	}

	g_initialized = true;
}

} // anonymous namespace

namespace wibo::heap {

bool initialize() {
	std::call_once(g_initOnce, initializeImpl);
	return g_initialized;
}

uintptr_t systemPageSize() {
	static uintptr_t cached = []() {
		long detected = sysconf(_SC_PAGESIZE);
		if (detected <= 0) {
			return static_cast<uintptr_t>(4096);
		}
		return static_cast<uintptr_t>(detected);
	}();
	return cached;
}

mi_heap_t *getGuestHeap() {
	initialize();
	if (g_guestHeap == nullptr) {
		g_guestHeap = createGuestHeap();
	}
	return g_guestHeap;
}

mi_heap_t *createGuestHeap() {
	initialize();
	if (g_guestArenaId != nullptr) {
		if (mi_heap_t *h = mi_heap_new_ex(0, true, g_guestArenaId)) {
			DEBUG_LOG("heap: created guest heap in arena %p\n", g_guestArenaId);
			return h;
		}
	}
	DEBUG_LOG("heap: created guest heap without arena\n");
	return mi_heap_new();
}

void *guestMalloc(std::size_t size) { return mi_heap_malloc(getGuestHeap(), size); }

void *guestCalloc(std::size_t count, std::size_t size) { return mi_heap_calloc(getGuestHeap(), count, size); }

void *guestRealloc(void *ptr, std::size_t newSize) { return mi_heap_realloc(getGuestHeap(), ptr, newSize); }

void guestFree(void *ptr) { mi_free(ptr); }

uintptr_t allocationGranularity() { return kVirtualAllocationGranularity; }

DWORD win32ErrorFromVmStatus(VmStatus status) {
	switch (status) {
	case VmStatus::Success:
		return ERROR_SUCCESS;
	case VmStatus::InvalidParameter:
		return ERROR_INVALID_PARAMETER;
	case VmStatus::InvalidAddress:
	case VmStatus::Rejected:
		return ERROR_INVALID_ADDRESS;
	case VmStatus::NoAccess:
		return ERROR_NOACCESS;
	case VmStatus::NotSupported:
		return ERROR_NOT_SUPPORTED;
	case VmStatus::NoMemory:
		return ERROR_NOT_ENOUGH_MEMORY;
	case VmStatus::UnknownError:
	default:
		return ERROR_INVALID_PARAMETER;
	}
}

NTSTATUS ntStatusFromVmStatus(VmStatus status) { return wibo::statusFromWinError(win32ErrorFromVmStatus(status)); }

VmStatus virtualReset(void *baseAddress, std::size_t regionSize) {
	if (!baseAddress) {
		return VmStatus::InvalidAddress;
	}
	if (regionSize == 0) {
		return VmStatus::InvalidParameter;
	}
	uintptr_t request = reinterpret_cast<uintptr_t>(baseAddress);
	if (addOverflows(request, regionSize)) {
		return VmStatus::InvalidParameter;
	}
	const uintptr_t pageSize = wibo::heap::systemPageSize();
	uintptr_t start = alignDown(request, pageSize);
	uintptr_t end = alignUp(request + static_cast<uintptr_t>(regionSize), pageSize);
	std::size_t length = static_cast<std::size_t>(end - start);
	if (length == 0) {
		return VmStatus::InvalidParameter;
	}
	std::unique_lock allocLock(g_virtualAllocMutex);
	VirtualAllocation *region = lookupRegion(start);
	if (!region || !rangeWithinRegion(*region, start, length)) {
		return VmStatus::InvalidAddress;
	}
	allocLock.unlock();
#ifdef MADV_FREE
	int advice = MADV_FREE;
#else
	int advice = MADV_DONTNEED;
#endif
	if (madvise(reinterpret_cast<void *>(start), length, advice) != 0) {
		return vmStatusFromErrno(errno);
	}
	return VmStatus::Success;
}

VmStatus virtualAlloc(void **baseAddress, std::size_t *regionSize, DWORD allocationType, DWORD protect, DWORD type) {
	if (!regionSize) {
		return VmStatus::InvalidParameter;
	}
	std::size_t requestedSize = *regionSize;
	if (requestedSize == 0) {
		return VmStatus::InvalidParameter;
	}
	void *requestedAddress = baseAddress ? *baseAddress : nullptr;

	DWORD unsupportedFlags = allocationType & (MEM_WRITE_WATCH | MEM_PHYSICAL | MEM_LARGE_PAGES | MEM_RESET_UNDO);
	if (unsupportedFlags != 0) {
		return VmStatus::NotSupported;
	}

	bool reserve = (allocationType & MEM_RESERVE) != 0;
	bool commit = (allocationType & MEM_COMMIT) != 0;
	bool reset = (allocationType & MEM_RESET) != 0;
	bool topDown = (allocationType & MEM_TOP_DOWN) != 0;

	if (!reserve && commit && requestedAddress == nullptr) {
		reserve = true;
	}

	const uintptr_t pageSize = wibo::heap::systemPageSize();
	if (reset) {
		if (reserve || commit) {
			return VmStatus::InvalidParameter;
		}
		if (requestedAddress == nullptr) {
			return VmStatus::InvalidAddress;
		}
		uintptr_t requestVal = reinterpret_cast<uintptr_t>(requestedAddress);
		uintptr_t start = alignDown(requestVal, pageSize);
		uintptr_t end = alignUp(requestVal + static_cast<uintptr_t>(requestedSize), pageSize);
		std::size_t length = static_cast<std::size_t>(end - start);
		VmStatus status = virtualReset(requestedAddress, requestedSize);
		if (status == VmStatus::Success) {
			if (baseAddress) {
				*baseAddress = reinterpret_cast<void *>(start);
			}
			*regionSize = length;
		}
		return status;
	}

	if (!reserve && !commit) {
		return VmStatus::InvalidParameter;
	}

	std::unique_lock allocLock(g_virtualAllocMutex);

	if (reserve) {
		uintptr_t base = 0;
		std::size_t length = 0;
		if (requestedAddress != nullptr) {
			uintptr_t request = reinterpret_cast<uintptr_t>(requestedAddress);
			base = alignDown(request, kVirtualAllocationGranularity);
			std::size_t offset = static_cast<std::size_t>(request - base);
			if (addOverflows(offset, requestedSize)) {
				return VmStatus::InvalidParameter;
			}
			std::size_t span = requestedSize + offset;
			uintptr_t alignedSpan = alignUp(static_cast<uintptr_t>(span), pageSize);
			if (alignedSpan == 0) {
				return VmStatus::InvalidParameter;
			}
			length = static_cast<std::size_t>(alignedSpan);
			if (length == 0) {
				return VmStatus::InvalidParameter;
			}
			if (base >= kTwoGB || (base + length) > kTwoGB) {
				return VmStatus::InvalidAddress;
			}
			if (overlapsExistingMapping(base, length)) {
				return VmStatus::InvalidAddress;
			}
		} else {
			uintptr_t aligned = alignUp(static_cast<uintptr_t>(requestedSize), pageSize);
			if (aligned == 0) {
				return VmStatus::InvalidParameter;
			}
			length = static_cast<std::size_t>(aligned);
			if (!findFreeMapping(length, kLowMemoryStart, kTopDownStart, topDown, &base)) {
				return VmStatus::NoMemory;
			}
			if (base >= kTwoGB || (base + length) > kTwoGB) {
				return VmStatus::NoMemory;
			}
		}

		int prot = commit ? posixProtectFromWin32(protect) : PROT_NONE;
		int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
		if (!commit) {
			flags |= MAP_NORESERVE;
		}
		void *mapped = mmap(reinterpret_cast<void *>(base), length, prot, flags, -1, 0);
		if (mapped == MAP_FAILED) {
			return vmStatusFromErrno(errno);
		}
		if (type == MEM_IMAGE) {
			prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, base, length, "wibo guest image");
		} else {
			prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, base, length, "wibo guest allocated");
		}
		uintptr_t actualBase = reinterpret_cast<uintptr_t>(mapped);
		VirtualAllocation allocation{};
		allocation.base = actualBase;
		allocation.size = length;
		allocation.allocationProtect = protect;
		allocation.type = type;
		allocation.pageProtect.assign(length / pageSize, commit ? protect : 0);
		g_virtualAllocations[actualBase] = std::move(allocation);
		refreshGuestMapping(g_virtualAllocations[actualBase]);

		if (baseAddress) {
			*baseAddress = reinterpret_cast<void *>(actualBase);
		}
		*regionSize = length;
		return VmStatus::Success;
	}

	if (requestedAddress == nullptr) {
		return VmStatus::InvalidAddress;
	}
	uintptr_t request = reinterpret_cast<uintptr_t>(requestedAddress);
	if (addOverflows(request, requestedSize)) {
		return VmStatus::InvalidParameter;
	}
	uintptr_t start = alignDown(request, pageSize);
	uintptr_t end = alignUp(request + static_cast<uintptr_t>(requestedSize), pageSize);
	std::size_t length = static_cast<std::size_t>(end - start);
	if (length == 0) {
		return VmStatus::InvalidParameter;
	}

	VirtualAllocation *region = lookupRegion(start);
	if (!region || !rangeWithinRegion(*region, start, length)) {
		return VmStatus::InvalidAddress;
	}

	const std::size_t pageCount = length / pageSize;
	std::vector<std::pair<uintptr_t, std::size_t>> runs;
	runs.reserve(pageCount);
	for (std::size_t i = 0; i < pageCount; ++i) {
		std::size_t pageIndex = ((start - region->base) / pageSize) + i;
		if (pageIndex >= region->pageProtect.size()) {
			return VmStatus::InvalidAddress;
		}
		if (region->pageProtect[pageIndex] != 0) {
			continue;
		}
		uintptr_t runBase = start + i * pageSize;
		std::size_t runLength = pageSize;
		while (i + 1 < pageCount) {
			std::size_t nextIndex = ((start - region->base) / pageSize) + i + 1;
			if (region->pageProtect[nextIndex] != 0) {
				break;
			}
			++i;
			runLength += pageSize;
		}
		runs.emplace_back(runBase, runLength);
	}

	for (const auto &run : runs) {
		void *res = mmap(reinterpret_cast<void *>(run.first), run.second, posixProtectFromWin32(protect),
						 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		if (res == MAP_FAILED) {
			return vmStatusFromErrno(errno);
		}
		prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, run.first, run.second, "wibo guest committed");
		markCommitted(*region, run.first, run.second, protect);
	}

	refreshGuestMapping(*region);

	if (baseAddress) {
		*baseAddress = reinterpret_cast<void *>(start);
	}
	*regionSize = length;
	return VmStatus::Success;
}

VmStatus virtualFree(void *baseAddress, std::size_t regionSize, DWORD freeType) {
	if (!baseAddress) {
		return VmStatus::InvalidAddress;
	}
	if ((freeType & (MEM_COALESCE_PLACEHOLDERS | MEM_PRESERVE_PLACEHOLDER)) != 0) {
		return VmStatus::NotSupported;
	}

	const bool release = (freeType & MEM_RELEASE) != 0;
	const bool decommit = (freeType & MEM_DECOMMIT) != 0;
	if (release == decommit) {
		return VmStatus::InvalidParameter;
	}

	const uintptr_t pageSize = wibo::heap::systemPageSize();
	std::unique_lock allocLock(g_virtualAllocMutex);

	if (release) {
		uintptr_t base = reinterpret_cast<uintptr_t>(baseAddress);
		auto it = g_virtualAllocations.find(base);
		if (it == g_virtualAllocations.end()) {
			auto containing = findRegionIterator(base);
			if (regionSize != 0 && containing != g_virtualAllocations.end()) {
				return VmStatus::InvalidParameter;
			}
			return VmStatus::InvalidAddress;
		}
		if (regionSize != 0) {
			return VmStatus::InvalidParameter;
		}
		std::size_t length = it->second.size;
		g_virtualAllocations.erase(it);
		allocLock.unlock();
		// Replace with PROT_NONE + MAP_NORESERVE to release physical memory
		void *res = mmap(reinterpret_cast<void *>(base), length, PROT_NONE,
						 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE, -1, 0);
		if (res == MAP_FAILED) {
			return vmStatusFromErrno(errno);
		}
		prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, base, length, "wibo reserved");
		eraseGuestMapping(base);
		return VmStatus::Success;
	}

	uintptr_t request = reinterpret_cast<uintptr_t>(baseAddress);
	auto regionIt = findRegionIterator(request);
	if (regionIt == g_virtualAllocations.end()) {
		return VmStatus::InvalidAddress;
	}
	VirtualAllocation &region = regionIt->second;
	uintptr_t start = alignDown(request, pageSize);
	uintptr_t end = 0;
	if (regionSize == 0) {
		if (request != region.base) {
			return VmStatus::InvalidParameter;
		}
		start = region.base;
		end = region.base + region.size;
	} else {
		if (addOverflows(request, regionSize)) {
			return VmStatus::InvalidParameter;
		}
		end = alignUp(request + static_cast<uintptr_t>(regionSize), pageSize);
	}
	if (end <= start) {
		return VmStatus::InvalidParameter;
	}
	std::size_t length = static_cast<std::size_t>(end - start);
	if (!rangeWithinRegion(region, start, length)) {
		return VmStatus::InvalidAddress;
	}
	void *res = mmap(reinterpret_cast<void *>(start), length, PROT_NONE,
					 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE, -1, 0);
	if (res == MAP_FAILED) {
		return vmStatusFromErrno(errno);
	}
	prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, res, length, "wibo reserved");
	markDecommitted(region, start, length);
	refreshGuestMapping(region);
	return VmStatus::Success;
}

VmStatus virtualProtect(void *baseAddress, std::size_t regionSize, DWORD newProtect, DWORD *oldProtect) {
	if (!baseAddress || regionSize == 0) {
		return VmStatus::InvalidParameter;
	}

	const std::size_t pageSize = systemPageSize();
	uintptr_t request = reinterpret_cast<uintptr_t>(baseAddress);
	uintptr_t start = alignDown(request, pageSize);
	uintptr_t end = alignUp(request + static_cast<uintptr_t>(regionSize), pageSize);
	if (end <= start) {
		return VmStatus::InvalidParameter;
	}

	std::unique_lock allocLock(g_virtualAllocMutex);
	VirtualAllocation *region = lookupRegion(start);
	if (!region || !rangeWithinRegion(*region, start, static_cast<std::size_t>(end - start))) {
		return VmStatus::InvalidAddress;
	}

	const std::size_t firstPage = (start - region->base) / pageSize;
	const std::size_t pageCount = (end - start) / pageSize;
	if (pageCount == 0) {
		return VmStatus::InvalidParameter;
	}

	DWORD previousProtect = region->pageProtect[firstPage];
	if (previousProtect == 0) {
		return VmStatus::NoAccess;
	}
	for (std::size_t i = 0; i < pageCount; ++i) {
		if (region->pageProtect[firstPage + i] == 0) {
			return VmStatus::NoAccess;
		}
	}

	int prot = posixProtectFromWin32(newProtect);
	if (mprotect(reinterpret_cast<void *>(start), end - start, prot) != 0) {
		return vmStatusFromErrno(errno);
	}
	for (std::size_t i = 0; i < pageCount; ++i) {
		region->pageProtect[firstPage + i] = newProtect;
	}
	refreshGuestMapping(*region);

	if (oldProtect) {
		*oldProtect = previousProtect;
	}
	return VmStatus::Success;
}

VmStatus virtualQuery(const void *address, MEMORY_BASIC_INFORMATION *outInfo) {
	if (!outInfo) {
		return VmStatus::InvalidParameter;
	}

	const std::size_t pageSize = systemPageSize();
	uintptr_t request = address ? reinterpret_cast<uintptr_t>(address) : 0;
	if (request >= kTwoGB) {
		return VmStatus::InvalidParameter;
	}
	uintptr_t pageBase = alignDown(request, pageSize);

	std::unique_lock allocLock(g_virtualAllocMutex);
	VirtualAllocation *region = lookupRegion(pageBase);
	if (!region) {
		uintptr_t regionStart = pageBase;
		uintptr_t regionEnd = regionStart;
		auto next = g_virtualAllocations.lower_bound(pageBase);
		if (next != g_virtualAllocations.end()) {
			regionEnd = next->second.base;
		} else {
			regionEnd = kTwoGB;
		}
		if (regionEnd <= regionStart) {
			regionEnd = regionStart + pageSize;
		}
		allocLock.unlock();
		outInfo->BaseAddress = reinterpret_cast<void *>(regionStart);
		outInfo->AllocationBase = nullptr;
		outInfo->AllocationProtect = 0;
		outInfo->RegionSize = regionEnd - regionStart;
		outInfo->State = MEM_FREE;
		outInfo->Protect = PAGE_NOACCESS;
		outInfo->Type = 0;
		return VmStatus::Success;
	}

	const uintptr_t regionLimit = region->base + region->size;
	const std::size_t pageIndex = (pageBase - region->base) / pageSize;
	if (pageIndex >= region->pageProtect.size()) {
		allocLock.unlock();
		return VmStatus::InvalidAddress;
	}
	const DWORD pageProtect = region->pageProtect[pageIndex];
	const bool committed = pageProtect != 0;
	uintptr_t blockStart = pageBase;
	uintptr_t blockEnd = pageBase + pageSize;
	while (blockStart > region->base) {
		std::size_t idx = (blockStart - region->base) / pageSize - 1;
		DWORD protect = region->pageProtect[idx];
		bool pageCommitted = protect != 0;
		if (pageCommitted != committed) {
			break;
		}
		if (committed && protect != pageProtect) {
			break;
		}
		blockStart -= pageSize;
	}
	while (blockEnd < regionLimit) {
		std::size_t idx = (blockEnd - region->base) / pageSize;
		if (idx >= region->pageProtect.size()) {
			break;
		}
		DWORD protect = region->pageProtect[idx];
		bool pageCommitted = protect != 0;
		if (pageCommitted != committed) {
			break;
		}
		if (committed && protect != pageProtect) {
			break;
		}
		blockEnd += pageSize;
	}
	DWORD allocationProtect = region->allocationProtect != 0 ? region->allocationProtect : PAGE_NOACCESS;
	DWORD finalProtect = committed ? pageProtect : PAGE_NOACCESS;
	allocLock.unlock();

	outInfo->BaseAddress = reinterpret_cast<void *>(blockStart);
	outInfo->AllocationBase = reinterpret_cast<void *>(region->base);
	outInfo->AllocationProtect = allocationProtect;
	outInfo->RegionSize = blockEnd - blockStart;
	outInfo->State = committed ? MEM_COMMIT : MEM_RESERVE;
	outInfo->Protect = finalProtect;
	outInfo->Type = region->type;
	return VmStatus::Success;
}

VmStatus reserveViewRange(std::size_t regionSize, uintptr_t minAddr, uintptr_t maxAddr, void **baseAddress) {
	if (!baseAddress || regionSize == 0) {
		return VmStatus::InvalidParameter;
	}
	const uintptr_t pageSize = wibo::heap::systemPageSize();
	std::size_t aligned = static_cast<std::size_t>(alignUp(static_cast<uintptr_t>(regionSize), pageSize));
	if (aligned == 0) {
		return VmStatus::InvalidParameter;
	}
	if (minAddr == 0) {
		minAddr = kLowMemoryStart;
	}
	if (maxAddr == 0) {
		maxAddr = kTopDownStart;
	}
	if (minAddr >= maxAddr || aligned > (maxAddr - minAddr)) {
		return VmStatus::InvalidParameter;
	}
	uintptr_t candidate = 0;
	if (!findFreeMapping(aligned, minAddr, maxAddr, false, &candidate)) {
		return VmStatus::NoMemory;
	}
	recordGuestMapping(candidate, aligned, PAGE_NOACCESS, MEM_RESERVE, PAGE_NOACCESS, MEM_MAPPED);
	*baseAddress = reinterpret_cast<void *>(candidate);
	return VmStatus::Success;
}

void registerViewRange(void *baseAddress, std::size_t regionSize, DWORD allocationProtect, DWORD protect) {
	if (!baseAddress) {
		return;
	}
	const uintptr_t pageSize = wibo::heap::systemPageSize();
	std::size_t aligned = static_cast<std::size_t>(alignUp(static_cast<uintptr_t>(regionSize), pageSize));
	recordGuestMapping(reinterpret_cast<uintptr_t>(baseAddress), aligned, allocationProtect, MEM_COMMIT, protect,
					   MEM_MAPPED);
}

void releaseViewRange(void *baseAddress) {
	if (!baseAddress) {
		return;
	}
	eraseGuestMapping(reinterpret_cast<uintptr_t>(baseAddress));
}

bool reserveGuestStack(std::size_t stackSizeBytes, void **outStackLimit, void **outStackBase) {
	const std::size_t ps = systemPageSize();
	std::size_t total = ((stackSizeBytes + (ps * 2) - 1) & ~(ps - 1));

	ArenaRange r;
	if (!mapArena(total, kTopDownStart, kTwoGB, true, "wibo guest stack", r)) {
		DEBUG_LOG("heap: reserveGuestStack: failed to map low region\n");
		return false;
	}

	// Protect the guard page at the bottom of the mapped region
	if (mprotect(r.start, ps, PROT_NONE) != 0) {
		// Non-fatal; continue without guard
		DEBUG_LOG("heap: reserveGuestStack: mprotect guard failed\n");
	}

	// Stack grows downwards; limit is after guard, base is top of mapping
	void *limit = static_cast<char *>(r.start) + ps;
	void *base = static_cast<char *>(r.start) + r.size;
	*outStackLimit = limit;
	*outStackBase = base;
	DEBUG_LOG("heap: reserved guest stack limit=%p base=%p (total=%zu KiB)\n", limit, base, r.size >> 10);
	return true;
}

} // namespace wibo::heap

static void debugPrintMaps() {
	char buf[1024];
	int fd = open("/proc/self/maps", O_RDONLY);
	if (fd == -1) {
		LOG_ERR("heap: failed to open /proc/self/maps\n");
		return;
	}
	while (true) {
		ssize_t r = read(fd, buf, sizeof(buf));
		if (r == 0) {
			break;
		} else if (r == -1) {
			LOG_ERR("heap: failed to read /proc/self/maps\n");
			close(fd);
			return;
		}
		write(STDERR_FILENO, buf, r);
	}
	close(fd);
}

constexpr size_t MAPS_BUFFER_SIZE = 0x10000;
constexpr size_t MAX_NUM_MAPPINGS = 128;

/**
 * Read /proc/self/maps into a buffer.
 *
 * While reading /proc/self/maps, we need to be extremely careful not to allocate any memory,
 * as that could cause libc to modify memory mappings while we're attempting to fill them.
 * To accomplish this, we use Linux syscalls directly.
 *
 * @param buffer The buffer to read into.
 * @return The number of bytes read.
 */
static size_t readMaps(char *buffer) {
	int fd = open("/proc/self/maps", O_RDONLY);
	if (fd == -1) {
		perror("heap: failed to open /proc/self/maps");
		exit(1);
	}

	char *cur = buffer;
	char *bufferEnd = buffer + MAPS_BUFFER_SIZE;
	while (cur < bufferEnd) {
		int ret = read(fd, cur, static_cast<size_t>(bufferEnd - cur));
		if (ret == -1) {
			if (errno == EINTR) {
				continue;
			}
			perror("heap: failed to read /proc/self/maps");
			exit(1);
		} else if (ret == 0) {
			break;
		}
		cur += ret;
	}
	close(fd);

	if (cur == bufferEnd) {
		fprintf(stderr, "heap: buffer too small while reading /proc/self/maps\n");
		exit(1);
	}
	*cur = '\0';
	return static_cast<size_t>(cur - buffer);
}

/**
 * Map the upper 2GB of memory to prevent libc from allocating there.
 *
 * This is necessary because 32-bit windows only reserves the lowest 2GB of memory for use by a process
 * (https://www.tenouk.com/WinVirtualAddressSpace.html). Linux, on the other hand, will happily allow
 * nearly the entire 4GB address space to be used. Some Windows programs rely on heap allocations to be
 * in the lower 2GB of memory, otherwise they misbehave or crash.
 *
 * Between reading /proc/self/maps and mmap-ing the upper 2GB, we must be extremely careful not to allocate
 * any memory, as that could cause libc to modify memory mappings while we're attempting to fill them.
 */
static size_t blockLower2GB(MEMORY_BASIC_INFORMATION mappings[MAX_NUM_MAPPINGS]) {
	// Buffer lives on the stack to avoid heap allocation
	char buffer[MAPS_BUFFER_SIZE];
	size_t len = readMaps(buffer);
	std::string_view procLine(buffer, len);
	uintptr_t lastMapEnd = mmapMinAddr();
	size_t numMappings = 0;
	while (true) {
		size_t newline = procLine.find('\n');
		if (newline == std::string::npos) {
			break;
		}

		uintptr_t mapStart = 0;
		const char *lineEnd = procLine.data() + procLine.size();
		auto result = std::from_chars(procLine.data(), lineEnd, mapStart, 16);
		if (result.ec != std::errc()) {
			break;
		}
		if (result.ptr >= lineEnd || *result.ptr != '-') {
			continue;
		}
		uintptr_t mapEnd = 0;
		result = std::from_chars(result.ptr + 1, lineEnd, mapEnd, 16);
		if (result.ec != std::errc()) {
			break;
		}
		if (mapStart == mapEnd || mapStart > mapEnd) {
			continue;
		}

		if (numMappings < MAX_NUM_MAPPINGS) {
			if (numMappings > 0) {
				auto &prevMapping = mappings[numMappings - 1];
				uintptr_t prevMapStart = reinterpret_cast<uintptr_t>(prevMapping.BaseAddress);
				uintptr_t prevMapEnd = prevMapStart + prevMapping.RegionSize;
				if (mapStart <= prevMapEnd) {
					// Extend the previous mapping
					prevMapping.RegionSize = mapEnd - prevMapStart;
					lastMapEnd = mapEnd;
					procLine = procLine.substr(newline + 1);
					continue;
				}
			}
			mappings[numMappings++] = (MEMORY_BASIC_INFORMATION){
				.BaseAddress = reinterpret_cast<void *>(mapStart),
				.AllocationBase = reinterpret_cast<void *>(mapStart),
				.AllocationProtect = PAGE_NOACCESS,
				.RegionSize = mapEnd - mapStart,
				.State = MEM_RESERVE,
				.Protect = PAGE_NOACCESS,
				.Type = 0, // external
			};
		}

		// The empty space we want to map out is now between lastMapEnd and mapStart
		uintptr_t reserveStart = lastMapEnd;
		uintptr_t reserveEnd = mapStart;

		if ((reserveEnd - reserveStart) != 0 && reserveStart < kTwoGB) {
			reserveEnd = std::min(reserveEnd, kTwoGB);

			uintptr_t len = reserveEnd - reserveStart;
			int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
#ifdef MAP_FIXED_NOREPLACE
			flags |= MAP_FIXED_NOREPLACE;
#else
			flags |= MAP_FIXED;
#endif
			void *ptr = mmap(reinterpret_cast<void *>(reserveStart), len, PROT_NONE, flags, -1, 0);
			if (ptr == MAP_FAILED) {
				perror("heap: failed reserve memory");
				exit(1);
			}
			prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ptr, len, "wibo reserved");
		}

		lastMapEnd = mapEnd;
		procLine = procLine.substr(newline + 1);
	}

	return numMappings;
}

#if defined(__clang__)
__attribute__((constructor(101)))
#else
__attribute__((constructor))
#endif
__attribute__((used)) static void wibo_heap_constructor() {
	MEMORY_BASIC_INFORMATION mappings[MAX_NUM_MAPPINGS];
	memset(mappings, 0, sizeof(mappings));
	bool debug = getenv("WIBO_DEBUG_HEAP") != nullptr;
	if (debug) {
		LOG_OUT("heap: initializing...\n");
		debugPrintMaps();
	}
	size_t numMappings = blockLower2GB(mappings);
	// Now we can allocate memory
	if (debug) {
		mi_option_enable(mi_option_show_stats);
		mi_option_enable(mi_option_verbose);
	}
	g_mappings = new std::map<uintptr_t, MEMORY_BASIC_INFORMATION>;
	for (size_t i = 0; i < numMappings; ++i) {
		if (debug) {
			fprintf(stderr, "Existing %zu: BaseAddress=%p, RegionSize=%lu\n", i, mappings[i].BaseAddress,
					mappings[i].RegionSize);
		}
		g_mappings->emplace(reinterpret_cast<uintptr_t>(mappings[i].BaseAddress), mappings[i]);
	}
}
