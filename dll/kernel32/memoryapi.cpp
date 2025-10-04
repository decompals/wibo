#include "memoryapi.h"
#include "common.h"
#include "errors.h"
#include "handles.h"
#include "internal.h"
#include "strutil.h"

#include <cerrno>
#include <fcntl.h>
#include <iterator>
#include <limits>
#include <map>
#include <mutex>
#include <sys/mman.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

constexpr size_t kVirtualAllocationGranularity = 64 * 1024;
constexpr uintptr_t kProcessAddressLimit = 0x80000000;

struct MappingObject : ObjectBase {
	static constexpr ObjectType kType = ObjectType::Mapping;

	std::mutex m;
	int fd = -1;
	size_t maxSize = 0;
	DWORD protect = 0;
	bool anonymous = false;
	bool closed = false;

	explicit MappingObject() : ObjectBase(kType) {}
	~MappingObject() override;
};

MappingObject::~MappingObject() {
	std::lock_guard lk(m);
	if (fd != -1) {
		close(fd);
		fd = -1;
	}
}

struct ViewInfo {
	uintptr_t viewBase = 0;
	size_t viewLength = 0;
	uintptr_t allocationBase = 0;
	size_t allocationLength = 0;
	Pin<MappingObject> owner;
	DWORD protect = PAGE_NOACCESS;
	DWORD allocationProtect = PAGE_NOACCESS;
	DWORD type = MEM_PRIVATE;
};

std::map<uintptr_t, ViewInfo> g_viewInfo;
std::mutex g_viewInfoMutex;

struct VirtualAllocation {
	uintptr_t base = 0;
	size_t size = 0;
	DWORD allocationProtect = 0;
	std::vector<DWORD> pageProtect;
};

std::map<uintptr_t, VirtualAllocation> g_virtualAllocations;
std::mutex g_virtualAllocMutex;

size_t systemPageSize() {
	static size_t cached = []() {
		long detected = sysconf(_SC_PAGESIZE);
		if (detected <= 0) {
			return static_cast<size_t>(4096);
		}
		return static_cast<size_t>(detected);
	}();
	return cached;
}

uintptr_t alignDown(uintptr_t value, size_t alignment) {
	const uintptr_t mask = static_cast<uintptr_t>(alignment) - 1;
	return value & ~mask;
}

uintptr_t alignUp(uintptr_t value, size_t alignment) {
	const uintptr_t mask = static_cast<uintptr_t>(alignment) - 1;
	if (mask == std::numeric_limits<uintptr_t>::max()) {
		return value;
	}
	if (value > std::numeric_limits<uintptr_t>::max() - mask) {
		return std::numeric_limits<uintptr_t>::max();
	}
	return (value + mask) & ~mask;
}

bool addOverflows(uintptr_t base, size_t amount) {
	return base > std::numeric_limits<uintptr_t>::max() - static_cast<uintptr_t>(amount);
}

uintptr_t regionEnd(const VirtualAllocation &region) { return region.base + region.size; }

bool rangeOverlapsLocked(uintptr_t base, size_t length) {
	if (length == 0) {
		return false;
	}
	if (addOverflows(base, length - 1)) {
		return true;
	}
	uintptr_t end = base + length;
	auto next = g_virtualAllocations.lower_bound(base);
	if (next != g_virtualAllocations.begin()) {
		auto prev = std::prev(next);
		if (regionEnd(prev->second) > base) {
			return true;
		}
	}
	if (next != g_virtualAllocations.end() && next->second.base < end) {
		return true;
	}
	return false;
}

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

bool rangeWithinRegion(const VirtualAllocation &region, uintptr_t start, size_t length) {
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

DWORD desiredAccessToProtect(DWORD desiredAccess, DWORD mappingProtect) {
	DWORD access = desiredAccess;
	if ((access & FILE_MAP_ALL_ACCESS) == FILE_MAP_ALL_ACCESS) {
		access |= FILE_MAP_READ | FILE_MAP_WRITE;
	}
	bool wantExecute = (access & FILE_MAP_EXECUTE) != 0;
	bool wantWrite = (access & FILE_MAP_WRITE) != 0;
	bool wantCopy = (access & FILE_MAP_COPY) != 0;
	bool wantRead = (access & (FILE_MAP_READ | FILE_MAP_WRITE | FILE_MAP_COPY)) != 0;
	if (wantCopy) {
		wantWrite = true;
	}
	const bool supportsWrite = mappingProtect == PAGE_READWRITE || mappingProtect == PAGE_EXECUTE_READWRITE ||
							   mappingProtect == PAGE_WRITECOPY || mappingProtect == PAGE_EXECUTE_WRITECOPY;
	const bool supportsCopy = mappingProtect == PAGE_WRITECOPY || mappingProtect == PAGE_EXECUTE_WRITECOPY;

	if (wantCopy && !supportsCopy) {
		wantCopy = false;
	}
	if (wantWrite && !supportsWrite) {
		if (supportsCopy) {
			wantCopy = true;
			wantWrite = false;
		} else {
			wantWrite = false;
		}
	}
	if (!wantRead && (mappingProtect == PAGE_READONLY || mappingProtect == PAGE_EXECUTE_READ ||
					  mappingProtect == PAGE_WRITECOPY || mappingProtect == PAGE_EXECUTE_WRITECOPY)) {
		wantRead = true;
	}

	DWORD protect = PAGE_NOACCESS;
	if (wantCopy && supportsCopy) {
		protect = wantExecute ? PAGE_EXECUTE_WRITECOPY : PAGE_WRITECOPY;
	} else if (wantExecute) {
		if (wantWrite) {
			protect = PAGE_EXECUTE_READWRITE;
		} else if (wantRead) {
			protect = PAGE_EXECUTE_READ;
		} else {
			protect = PAGE_EXECUTE;
		}
	} else {
		if (wantWrite) {
			protect = PAGE_READWRITE;
		} else if (wantRead) {
			protect = PAGE_READONLY;
		}
	}
	if ((mappingProtect & PAGE_NOCACHE) != 0) {
		protect |= PAGE_NOCACHE;
	}
	if ((mappingProtect & PAGE_GUARD) != 0) {
		protect |= PAGE_GUARD;
	}
	if ((mappingProtect & PAGE_WRITECOMBINE) != 0) {
		protect |= PAGE_WRITECOMBINE;
	}
	return protect;
}

void markCommitted(VirtualAllocation &region, uintptr_t start, size_t length, DWORD protect) {
	if (length == 0) {
		return;
	}
	const size_t pageSize = systemPageSize();
	const size_t firstPage = (start - region.base) / pageSize;
	const size_t pageCount = length / pageSize;
	for (size_t i = 0; i < pageCount; ++i) {
		region.pageProtect[firstPage + i] = protect;
	}
}

void markDecommitted(VirtualAllocation &region, uintptr_t start, size_t length) {
	if (length == 0) {
		return;
	}
	const size_t pageSize = systemPageSize();
	const size_t firstPage = (start - region.base) / pageSize;
	const size_t pageCount = length / pageSize;
	for (size_t i = 0; i < pageCount; ++i) {
		region.pageProtect[firstPage + i] = 0;
	}
}

bool moduleRegionForAddress(uintptr_t pageBase, MEMORY_BASIC_INFORMATION &info) {
	if (pageBase == 0) {
		return false;
	}
	wibo::ModuleInfo *module = wibo::moduleInfoFromAddress(reinterpret_cast<void *>(pageBase));
	if (!module || !module->executable) {
		return false;
	}
	const auto &sections = module->executable->sections;
	if (sections.empty()) {
		return false;
	}
	size_t matchIndex = sections.size();
	for (size_t i = 0; i < sections.size(); ++i) {
		const auto &section = sections[i];
		if (pageBase >= section.base && pageBase < section.base + section.size) {
			matchIndex = i;
			break;
		}
	}
	if (matchIndex == sections.size()) {
		return false;
	}
	uintptr_t blockStart = sections[matchIndex].base;
	uintptr_t blockEnd = sections[matchIndex].base + sections[matchIndex].size;
	DWORD blockProtect = sections[matchIndex].protect;
	for (size_t prev = matchIndex; prev > 0;) {
		--prev;
		const auto &section = sections[prev];
		if (section.base + section.size != blockStart) {
			break;
		}
		if (section.protect != blockProtect) {
			break;
		}
		blockStart = section.base;
	}
	for (size_t next = matchIndex + 1; next < sections.size(); ++next) {
		const auto &section = sections[next];
		if (section.base != blockEnd) {
			break;
		}
		if (section.protect != blockProtect) {
			break;
		}
		blockEnd = section.base + section.size;
	}
	info.BaseAddress = reinterpret_cast<void *>(blockStart);
	info.AllocationBase = module->executable->imageBase;
	info.AllocationProtect = blockProtect;
	info.RegionSize = blockEnd > blockStart ? blockEnd - blockStart : 0;
	info.State = MEM_COMMIT;
	info.Protect = blockProtect;
	info.Type = MEM_IMAGE;
	return true;
}

bool mappedViewRegionForAddress(uintptr_t request, uintptr_t pageBase, MEMORY_BASIC_INFORMATION &info) {
	std::lock_guard guard(g_viewInfoMutex);
	if (g_viewInfo.empty()) {
		return false;
	}
	const size_t pageSize = systemPageSize();
	for (const auto &entry : g_viewInfo) {
		const ViewInfo &view = entry.second;
		if (view.viewLength == 0) {
			continue;
		}
		uintptr_t allocationStart = view.allocationBase;
		uintptr_t allocationEnd = allocationStart + view.allocationLength;
		if (pageBase < allocationStart || pageBase >= allocationEnd) {
			continue;
		}
		uintptr_t viewStart = view.viewBase;
		uintptr_t viewEnd = view.viewBase + view.viewLength;
		if (request != 0 && (request < viewStart || request >= viewEnd)) {
			continue;
		}
		uintptr_t blockStart = viewStart;
		uintptr_t blockEnd = alignUp(viewEnd, pageSize);
		info.BaseAddress = reinterpret_cast<void *>(blockStart);
		info.AllocationBase = reinterpret_cast<void *>(view.viewBase);
		info.AllocationProtect = view.allocationProtect;
		info.RegionSize = blockEnd > blockStart ? blockEnd - blockStart : 0;
		info.State = MEM_COMMIT;
		info.Protect = view.protect;
		info.Type = view.type;
		return true;
	}
	return false;
}

bool virtualAllocationRegionForAddress(uintptr_t pageBase, MEMORY_BASIC_INFORMATION &info) {
	const size_t pageSize = systemPageSize();
	std::unique_lock lk(g_virtualAllocMutex);
	VirtualAllocation *region = lookupRegion(pageBase);
	if (!region) {
		uintptr_t regionStart = pageBase;
		uintptr_t regionEnd = regionStart;
		auto next = g_virtualAllocations.lower_bound(pageBase);
		if (next != g_virtualAllocations.end()) {
			regionEnd = next->second.base;
		} else {
			regionEnd = kProcessAddressLimit;
		}
		if (regionEnd <= regionStart) {
			regionEnd = regionStart + pageSize;
		}
		lk.unlock();
		info.BaseAddress = reinterpret_cast<void *>(regionStart);
		info.AllocationBase = nullptr;
		info.AllocationProtect = 0;
		info.RegionSize = regionEnd - regionStart;
		info.State = MEM_FREE;
		info.Protect = PAGE_NOACCESS;
		info.Type = 0;
		return true;
	}
	const uintptr_t regionLimit = region->base + region->size;
	const size_t pageIndex = (pageBase - region->base) / pageSize;
	if (pageIndex >= region->pageProtect.size()) {
		return false;
	}
	const DWORD pageProtect = region->pageProtect[pageIndex];
	const bool committed = pageProtect != 0;
	uintptr_t blockStart = pageBase;
	uintptr_t blockEnd = pageBase + pageSize;
	while (blockStart > region->base) {
		size_t idx = (blockStart - region->base) / pageSize - 1;
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
		size_t idx = (blockEnd - region->base) / pageSize;
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
	uintptr_t allocationBase = region->base;
	DWORD allocationProtect = region->allocationProtect != 0 ? region->allocationProtect : PAGE_NOACCESS;
	DWORD finalProtect = committed ? pageProtect : PAGE_NOACCESS;
	lk.unlock();
	info.BaseAddress = reinterpret_cast<void *>(blockStart);
	info.AllocationBase = reinterpret_cast<void *>(allocationBase);
	info.AllocationProtect = allocationProtect;
	info.RegionSize = blockEnd - blockStart;
	info.State = committed ? MEM_COMMIT : MEM_RESERVE;
	info.Protect = finalProtect;
	info.Type = MEM_PRIVATE;
	return true;
}

void *alignedReserve(size_t length, int prot, int flags) {
	const size_t granularity = kVirtualAllocationGranularity;
	const size_t request = length + granularity;
	void *raw = mmap(nullptr, request, prot, flags, -1, 0);
	if (raw == MAP_FAILED) {
		return MAP_FAILED;
	}
	uintptr_t rawAddr = reinterpret_cast<uintptr_t>(raw);
	uintptr_t aligned = alignUp(rawAddr, granularity);
	size_t front = aligned - rawAddr;
	size_t back = (rawAddr + request) - (aligned + length);
	if (front != 0) {
		if (munmap(raw, front) != 0) {
			munmap(raw, request);
			return MAP_FAILED;
		}
	}
	if (back != 0) {
		if (munmap(reinterpret_cast<void *>(aligned + length), back) != 0) {
			munmap(reinterpret_cast<void *>(aligned), length);
			return MAP_FAILED;
		}
	}
	return reinterpret_cast<void *>(aligned);
}

int translateProtect(DWORD flProtect) {
	switch (flProtect) {
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
		DEBUG_LOG("Unhandled flProtect: %u, defaulting to RW\n", flProtect);
		return PROT_READ | PROT_WRITE;
	}
}

} // namespace

namespace kernel32 {

HANDLE WIN_FUNC CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect,
								   DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName) {
	DEBUG_LOG("CreateFileMappingA(%p, %p, %u, %u, %u, %s)\n", hFile, lpFileMappingAttributes, flProtect,
			  dwMaximumSizeHigh, dwMaximumSizeLow, lpName ? lpName : "(null)");
	(void)lpFileMappingAttributes;
	(void)lpName;

	uint64_t size = (static_cast<uint64_t>(dwMaximumSizeHigh) << 32) | dwMaximumSizeLow;
	if (flProtect != PAGE_READONLY && flProtect != PAGE_READWRITE && flProtect != PAGE_WRITECOPY) {
		DEBUG_LOG("CreateFileMappingA: unsupported protection 0x%x\n", flProtect);
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}

	auto mapping = make_pin<MappingObject>();
	mapping->protect = flProtect;

	if (hFile == INVALID_HANDLE_VALUE) {
		mapping->anonymous = true;
		mapping->fd = -1;
		if (size == 0) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return nullptr;
		}
		mapping->maxSize = size;
	} else {
		auto file = wibo::handles().getAs<FileObject>(hFile);
		if (!file || !file->valid()) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return nullptr;
		}
		int dupFd = fcntl(file->fd, F_DUPFD_CLOEXEC, 0);
		if (dupFd == -1) {
			setLastErrorFromErrno();
			return nullptr;
		}
		mapping->fd = dupFd;
		if (size == 0) {
			off64_t fileSize = lseek64(dupFd, 0, SEEK_END);
			if (fileSize < 0) {
				return nullptr;
			}
			size = static_cast<uint64_t>(fileSize);
		}
		mapping->maxSize = size;
	}

	wibo::lastError = ERROR_SUCCESS;
	return wibo::handles().alloc(std::move(mapping), 0, 0);
}

HANDLE WIN_FUNC CreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect,
								   DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName) {
	DEBUG_LOG("CreateFileMappingW -> ");
	std::string name = wideStringToString(lpName);
	return CreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow,
							  lpName ? name.c_str() : nullptr);
}

static LPVOID mapViewOfFileInternal(Pin<MappingObject> mapping, DWORD dwDesiredAccess, uint64_t offset,
									SIZE_T dwNumberOfBytesToMap, LPVOID baseAddress) {
	if (!mapping) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return nullptr;
	}
	if (mapping->closed) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return nullptr;
	}
	if (mapping->anonymous && offset != 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}
	size_t maxSize = mapping->maxSize;
	uint64_t length = static_cast<uint64_t>(dwNumberOfBytesToMap);
	if (length == 0) {
		if (maxSize == 0 || offset > maxSize) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return nullptr;
		}
		length = maxSize - offset;
	}
	if (length == 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}
	if (maxSize != 0 && offset + length > maxSize) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}

	bool wantWrite = (dwDesiredAccess & FILE_MAP_WRITE) != 0;
	bool wantExecute = (dwDesiredAccess & FILE_MAP_EXECUTE) != 0;
	bool wantCopy = (dwDesiredAccess & FILE_MAP_COPY) != 0;
	bool wantAllAccess = (dwDesiredAccess & FILE_MAP_ALL_ACCESS) == FILE_MAP_ALL_ACCESS;
	if (wantAllAccess) {
		wantWrite = true;
	}
	int prot = PROT_READ;
	if (mapping->protect == PAGE_READWRITE) {
		if (wantWrite || wantCopy) {
			prot |= PROT_WRITE;
		}
	} else {
		if (wantWrite && !wantCopy) {
			wibo::lastError = ERROR_ACCESS_DENIED;
			return nullptr;
		}
		if (wantCopy) {
			prot |= PROT_WRITE;
		}
	}
	if (wantExecute) {
		prot |= PROT_EXEC;
	}

	int flags = (mapping->anonymous ? MAP_ANONYMOUS : 0) | (wantCopy ? MAP_PRIVATE : MAP_SHARED);
	const size_t pageSize = systemPageSize();
	off_t alignedOffset = mapping->anonymous ? 0 : static_cast<off_t>(offset & ~static_cast<uint64_t>(pageSize - 1));
	size_t offsetDelta = static_cast<size_t>(offset - static_cast<uint64_t>(alignedOffset));
	uint64_t requestedLength = length + offsetDelta;
	if (requestedLength < length) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}
	size_t mapLength = static_cast<size_t>(requestedLength);
	if (static_cast<uint64_t>(mapLength) != requestedLength) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}

	int mmapFd = mapping->anonymous ? -1 : mapping->fd;
	void *requestedBase = nullptr;
	int mapFlags = flags;
	if (baseAddress) {
		uintptr_t baseAddr = reinterpret_cast<uintptr_t>(baseAddress);
		if (baseAddr == 0 || (baseAddr % kVirtualAllocationGranularity) != 0) {
			wibo::lastError = ERROR_INVALID_ADDRESS;
			return nullptr;
		}
		if (offsetDelta > baseAddr) {
			wibo::lastError = ERROR_INVALID_ADDRESS;
			return nullptr;
		}
		uintptr_t mapBaseAddr = baseAddr - offsetDelta;
		if ((mapBaseAddr & (pageSize - 1)) != 0) {
			wibo::lastError = ERROR_INVALID_ADDRESS;
			return nullptr;
		}
		requestedBase = reinterpret_cast<void *>(mapBaseAddr);
#ifdef MAP_FIXED_NOREPLACE
		mapFlags |= MAP_FIXED_NOREPLACE;
#else
		mapFlags |= MAP_FIXED;
#endif
	}

	errno = 0;
	void *mapBase = mmap(requestedBase, mapLength, prot, mapFlags, mmapFd, alignedOffset);
	if (mapBase == MAP_FAILED) {
		int err = errno;
		if (baseAddress && (err == ENOMEM || err == EEXIST || err == EINVAL || err == EPERM)) {
			wibo::lastError = ERROR_INVALID_ADDRESS;
		} else {
			wibo::lastError = wibo::winErrorFromErrno(err);
		}
		return nullptr;
	}
	void *viewPtr = static_cast<uint8_t *>(mapBase) + offsetDelta;
	if (baseAddress && viewPtr != baseAddress) {
		munmap(mapBase, mapLength);
		wibo::lastError = ERROR_INVALID_ADDRESS;
		return nullptr;
	}
	uintptr_t viewLength = static_cast<uintptr_t>(length);
	uintptr_t alignedViewLength = alignUp(viewLength, pageSize);
	if (alignedViewLength == std::numeric_limits<uintptr_t>::max()) {
		alignedViewLength = viewLength;
	}
	DWORD protect = mapping->protect;
	ViewInfo view{};
	view.viewBase = reinterpret_cast<uintptr_t>(viewPtr);
	view.viewLength = static_cast<size_t>(alignedViewLength);
	view.allocationBase = reinterpret_cast<uintptr_t>(mapBase);
	view.allocationLength = mapLength;
	view.owner = std::move(mapping);
	view.protect = desiredAccessToProtect(dwDesiredAccess, protect);
	view.allocationProtect = protect;
	view.type = MEM_MAPPED;
	{
		std::lock_guard guard(g_viewInfoMutex);
		g_viewInfo.emplace(view.viewBase, std::move(view));
	}
	wibo::lastError = ERROR_SUCCESS;
	return viewPtr;
}

LPVOID WIN_FUNC MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh,
							  DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap) {
	DEBUG_LOG("MapViewOfFile(%p, 0x%x, %u, %u, %zu)\n", hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh,
			  dwFileOffsetLow, dwNumberOfBytesToMap);

	auto mapping = wibo::handles().getAs<MappingObject>(hFileMappingObject);
	if (!mapping) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return nullptr;
	}
	uint64_t offset = (static_cast<uint64_t>(dwFileOffsetHigh) << 32) | dwFileOffsetLow;
	return mapViewOfFileInternal(std::move(mapping), dwDesiredAccess, offset, dwNumberOfBytesToMap, nullptr);
}

LPVOID WIN_FUNC MapViewOfFileEx(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh,
								DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress) {
	DEBUG_LOG("MapViewOfFileEx(%p, 0x%x, %u, %u, %zu, %p)\n", hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh,
			  dwFileOffsetLow, dwNumberOfBytesToMap, lpBaseAddress);

	auto mapping = wibo::handles().getAs<MappingObject>(hFileMappingObject);
	if (!mapping) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return nullptr;
	}
	uint64_t offset = (static_cast<uint64_t>(dwFileOffsetHigh) << 32) | dwFileOffsetLow;
	return mapViewOfFileInternal(std::move(mapping), dwDesiredAccess, offset, dwNumberOfBytesToMap, lpBaseAddress);
}

BOOL WIN_FUNC UnmapViewOfFile(LPCVOID lpBaseAddress) {
	DEBUG_LOG("UnmapViewOfFile(%p)\n", lpBaseAddress);
	std::unique_lock lk(g_viewInfoMutex);
	auto it = g_viewInfo.find(reinterpret_cast<uintptr_t>(lpBaseAddress));
	if (it == g_viewInfo.end()) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	void *base = reinterpret_cast<void *>(it->second.allocationBase);
	size_t length = it->second.allocationLength;
	g_viewInfo.erase(it);
	lk.unlock();
	if (length != 0) {
		munmap(base, length);
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

LPVOID WIN_FUNC VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	DEBUG_LOG("VirtualAlloc(%p, %zu, %u, %u)\n", lpAddress, dwSize, flAllocationType, flProtect);

	if (dwSize == 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}

	DWORD unsupportedFlags = flAllocationType & (MEM_WRITE_WATCH | MEM_PHYSICAL | MEM_LARGE_PAGES | MEM_RESET_UNDO);
	if (unsupportedFlags != 0) {
		DEBUG_LOG("VirtualAlloc unsupported flags: 0x%x\n", unsupportedFlags);
		wibo::lastError = ERROR_NOT_SUPPORTED;
		return nullptr;
	}

	bool reserve = (flAllocationType & MEM_RESERVE) != 0;
	bool commit = (flAllocationType & MEM_COMMIT) != 0;
	bool reset = (flAllocationType & MEM_RESET) != 0;

	if (!reserve && commit && lpAddress == nullptr) {
		reserve = true;
	}

	if (reset) {
		if (reserve || commit) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return nullptr;
		}
		if (!lpAddress) {
			wibo::lastError = ERROR_INVALID_ADDRESS;
			return nullptr;
		}
		const size_t pageSize = systemPageSize();
		uintptr_t request = reinterpret_cast<uintptr_t>(lpAddress);
		if (addOverflows(request, static_cast<size_t>(dwSize))) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return nullptr;
		}
		uintptr_t start = alignDown(request, pageSize);
		uintptr_t end = alignUp(request + static_cast<uintptr_t>(dwSize), pageSize);
		size_t length = static_cast<size_t>(end - start);
		std::unique_lock lk(g_virtualAllocMutex);
		VirtualAllocation *region = lookupRegion(start);
		if (!region || !rangeWithinRegion(*region, start, length)) {
			wibo::lastError = ERROR_INVALID_ADDRESS;
			return nullptr;
		}
#ifdef MADV_FREE
		int advice = MADV_FREE;
#else
		int advice = MADV_DONTNEED;
#endif
		if (madvise(reinterpret_cast<void *>(start), length, advice) != 0) {
			wibo::lastError = wibo::winErrorFromErrno(errno);
			return nullptr;
		}
		wibo::lastError = ERROR_SUCCESS;
		return reinterpret_cast<LPVOID>(start);
	}

	if (!reserve && !commit) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}

	const size_t pageSize = systemPageSize();
	std::unique_lock lk(g_virtualAllocMutex);

	if (reserve) {
		uintptr_t base = 0;
		size_t length = 0;
		if (lpAddress) {
			uintptr_t request = reinterpret_cast<uintptr_t>(lpAddress);
			base = alignDown(request, kVirtualAllocationGranularity);
			size_t offset = static_cast<size_t>(request - base);
			if (addOverflows(offset, static_cast<size_t>(dwSize))) {
				wibo::lastError = ERROR_INVALID_PARAMETER;
				return nullptr;
			}
			size_t span = static_cast<size_t>(dwSize) + offset;
			uintptr_t alignedSpan = alignUp(span, pageSize);
			if (alignedSpan == std::numeric_limits<uintptr_t>::max()) {
				wibo::lastError = ERROR_INVALID_PARAMETER;
				return nullptr;
			}
			length = static_cast<size_t>(alignedSpan);
			if (length == 0 || rangeOverlapsLocked(base, length)) {
				wibo::lastError = ERROR_INVALID_ADDRESS;
				return nullptr;
			}
		} else {
			uintptr_t aligned = alignUp(static_cast<uintptr_t>(dwSize), pageSize);
			if (aligned == std::numeric_limits<uintptr_t>::max() || aligned == 0) {
				wibo::lastError = ERROR_INVALID_PARAMETER;
				return nullptr;
			}
			length = static_cast<size_t>(aligned);
		}
		const int prot = commit ? translateProtect(flProtect) : PROT_NONE;
		int flags = MAP_PRIVATE | MAP_ANONYMOUS;
		if (!commit) {
			flags |= MAP_NORESERVE;
		}
		void *result = MAP_FAILED;
		if (lpAddress) {
#ifdef MAP_FIXED_NOREPLACE
			flags |= MAP_FIXED_NOREPLACE;
#else
			flags |= MAP_FIXED;
#endif
			result = mmap(reinterpret_cast<void *>(base), length, prot, flags, -1, 0);
		} else {
			result = alignedReserve(length, prot, flags);
		}
		if (result == MAP_FAILED) {
			wibo::lastError = wibo::winErrorFromErrno(errno);
			return nullptr;
		}
		if (reinterpret_cast<uintptr_t>(result) >= 0x80000000) {
			munmap(result, length);
			wibo::lastError = ERROR_NOT_ENOUGH_MEMORY;
			return nullptr;
		}
		uintptr_t actualBase = reinterpret_cast<uintptr_t>(result);
		VirtualAllocation allocation{};
		allocation.base = actualBase;
		allocation.size = length;
		allocation.allocationProtect = flProtect;
		allocation.pageProtect.assign(length / pageSize, commit ? flProtect : 0);
		g_virtualAllocations[actualBase] = std::move(allocation);
		wibo::lastError = ERROR_SUCCESS;
		return result;
	}

	uintptr_t request = reinterpret_cast<uintptr_t>(lpAddress);
	if (addOverflows(request, static_cast<size_t>(dwSize))) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}
	uintptr_t start = alignDown(request, pageSize);
	uintptr_t end = alignUp(request + static_cast<uintptr_t>(dwSize), pageSize);
	size_t length = static_cast<size_t>(end - start);
	if (length == 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}
	VirtualAllocation *region = lookupRegion(start);
	if (!region || !rangeWithinRegion(*region, start, length)) {
		wibo::lastError = ERROR_INVALID_ADDRESS;
		return nullptr;
	}
	const size_t pageCount = length / pageSize;
	std::vector<std::pair<uintptr_t, size_t>> committedRuns;
	committedRuns.reserve(pageCount);
	for (size_t i = 0; i < pageCount; ++i) {
		size_t pageIndex = ((start - region->base) / pageSize) + i;
		if (pageIndex >= region->pageProtect.size()) {
			wibo::lastError = ERROR_INVALID_ADDRESS;
			return nullptr;
		}
		if (region->pageProtect[pageIndex] != 0) {
			continue;
		}
		uintptr_t runBase = start + i * pageSize;
		size_t runLength = pageSize;
		while (i + 1 < pageCount) {
			size_t nextIndex = ((start - region->base) / pageSize) + i + 1;
			if (region->pageProtect[nextIndex] != 0) {
				break;
			}
			++i;
			runLength += pageSize;
		}
		committedRuns.emplace_back(runBase, runLength);
	}
	for (const auto &run : committedRuns) {
		void *result = mmap(reinterpret_cast<void *>(run.first), run.second, translateProtect(flProtect),
							MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		if (result == MAP_FAILED) {
			wibo::lastError = wibo::winErrorFromErrno(errno);
			return nullptr;
		}
		markCommitted(*region, run.first, run.second, flProtect);
	}
	wibo::lastError = ERROR_SUCCESS;
	DEBUG_LOG("VirtualAlloc commit success -> %p\n", reinterpret_cast<void *>(start));
	return reinterpret_cast<LPVOID>(start);
}

BOOL WIN_FUNC VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
	DEBUG_LOG("VirtualFree(%p, %zu, %u)\n", lpAddress, dwSize, dwFreeType);
	if (!lpAddress) {
		wibo::lastError = ERROR_INVALID_ADDRESS;
		return FALSE;
	}

	if ((dwFreeType & (MEM_COALESCE_PLACEHOLDERS | MEM_PRESERVE_PLACEHOLDER)) != 0) {
		wibo::lastError = ERROR_NOT_SUPPORTED;
		return FALSE;
	}

	const bool release = (dwFreeType & MEM_RELEASE) != 0;
	const bool decommit = (dwFreeType & MEM_DECOMMIT) != 0;
	if (release == decommit) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	const size_t pageSize = systemPageSize();
	std::unique_lock lk(g_virtualAllocMutex);

	if (release) {
		uintptr_t base = reinterpret_cast<uintptr_t>(lpAddress);
		auto exact = g_virtualAllocations.find(base);
		if (exact == g_virtualAllocations.end()) {
			auto containing = findRegionIterator(base);
			if (dwSize != 0 && containing != g_virtualAllocations.end()) {
				wibo::lastError = ERROR_INVALID_PARAMETER;
			} else {
				wibo::lastError = ERROR_INVALID_ADDRESS;
			}
			return FALSE;
		}
		if (dwSize != 0) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		size_t length = exact->second.size;
		g_virtualAllocations.erase(exact);
		lk.unlock();
		if (munmap(lpAddress, length) != 0) {
			wibo::lastError = wibo::winErrorFromErrno(errno);
			return FALSE;
		}
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	uintptr_t request = reinterpret_cast<uintptr_t>(lpAddress);
	auto regionIt = findRegionIterator(request);
	if (regionIt == g_virtualAllocations.end()) {
		wibo::lastError = ERROR_INVALID_ADDRESS;
		return FALSE;
	}
	VirtualAllocation &region = regionIt->second;
	uintptr_t start = alignDown(request, pageSize);
	uintptr_t end = 0;
	if (dwSize == 0) {
		if (request != region.base) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		start = region.base;
		end = region.base + region.size;
	} else {
		if (addOverflows(request, static_cast<size_t>(dwSize))) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		end = alignUp(request + static_cast<uintptr_t>(dwSize), pageSize);
	}
	if (end <= start) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	size_t length = static_cast<size_t>(end - start);
	if (!rangeWithinRegion(region, start, length)) {
		wibo::lastError = ERROR_INVALID_ADDRESS;
		return FALSE;
	}
	void *result = mmap(reinterpret_cast<void *>(start), length, PROT_NONE,
						MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_NORESERVE, -1, 0);
	if (result == MAP_FAILED) {
		wibo::lastError = wibo::winErrorFromErrno(errno);
		return FALSE;
	}
	markDecommitted(region, start, length);
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
	DEBUG_LOG("VirtualProtect(%p, %zu, %u)\n", lpAddress, dwSize, flNewProtect);
	if (!lpAddress || dwSize == 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	const size_t pageSize = systemPageSize();
	uintptr_t request = reinterpret_cast<uintptr_t>(lpAddress);
	uintptr_t start = alignDown(request, pageSize);
	uintptr_t end = alignUp(request + static_cast<uintptr_t>(dwSize), pageSize);
	if (end <= start) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	std::unique_lock lk(g_virtualAllocMutex);
	VirtualAllocation *region = lookupRegion(start);
	if (!region || !rangeWithinRegion(*region, start, static_cast<size_t>(end - start))) {
		wibo::lastError = ERROR_INVALID_ADDRESS;
		return FALSE;
	}

	const size_t firstPage = (start - region->base) / pageSize;
	const size_t pageCount = (end - start) / pageSize;
	if (pageCount == 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	DWORD previousProtect = region->pageProtect[firstPage];
	if (previousProtect == 0) {
		wibo::lastError = ERROR_NOACCESS;
		return FALSE;
	}
	for (size_t i = 0; i < pageCount; ++i) {
		if (region->pageProtect[firstPage + i] == 0) {
			wibo::lastError = ERROR_NOACCESS;
			return FALSE;
		}
	}

	int prot = translateProtect(flNewProtect);
	if (mprotect(reinterpret_cast<void *>(start), end - start, prot) != 0) {
		wibo::lastError = wibo::winErrorFromErrno(errno);
		return FALSE;
	}
	for (size_t i = 0; i < pageCount; ++i) {
		region->pageProtect[firstPage + i] = flNewProtect;
	}
	lk.unlock();

	if (lpflOldProtect) {
		*lpflOldProtect = previousProtect;
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

SIZE_T WIN_FUNC VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
	DEBUG_LOG("VirtualQuery(%p, %p, %zu)\n", lpAddress, lpBuffer, dwLength);
	if (!lpBuffer || dwLength < sizeof(MEMORY_BASIC_INFORMATION)) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		DEBUG_LOG("-> ERROR_INVALID_PARAMETER\n");
		return 0;
	}

	std::memset(lpBuffer, 0, sizeof(MEMORY_BASIC_INFORMATION));
	const size_t pageSize = systemPageSize();
	uintptr_t request = lpAddress ? reinterpret_cast<uintptr_t>(lpAddress) : 0;
	uintptr_t pageBase = alignDown(request, pageSize);
	if (pageBase >= kProcessAddressLimit) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		DEBUG_LOG("-> ERROR_INVALID_PARAMETER (beyond address space)\n");
		return 0;
	}

	MEMORY_BASIC_INFORMATION info{};
	if (moduleRegionForAddress(pageBase, info)) {
		*lpBuffer = info;
		wibo::lastError = ERROR_SUCCESS;
		return sizeof(MEMORY_BASIC_INFORMATION);
	}
	if (mappedViewRegionForAddress(request, pageBase, info)) {
		*lpBuffer = info;
		wibo::lastError = ERROR_SUCCESS;
		return sizeof(MEMORY_BASIC_INFORMATION);
	}
	if (virtualAllocationRegionForAddress(pageBase, info)) {
		*lpBuffer = info;
		wibo::lastError = ERROR_SUCCESS;
		return sizeof(MEMORY_BASIC_INFORMATION);
	}

	wibo::lastError = ERROR_INVALID_ADDRESS;
	DEBUG_LOG("-> ERROR_INVALID_ADDRESS\n");
	return 0;
}

BOOL WIN_FUNC GetProcessWorkingSetSize(HANDLE hProcess, PSIZE_T lpMinimumWorkingSetSize,
									   PSIZE_T lpMaximumWorkingSetSize) {
	DEBUG_LOG("GetProcessWorkingSetSize(%p, %p, %p)\n", hProcess, lpMinimumWorkingSetSize, lpMaximumWorkingSetSize);
	(void)hProcess;
	if (!lpMinimumWorkingSetSize || !lpMaximumWorkingSetSize) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	*lpMinimumWorkingSetSize = 32 * 1024 * 1024;  // 32 MiB stub
	*lpMaximumWorkingSetSize = 128 * 1024 * 1024; // 128 MiB stub
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC SetProcessWorkingSetSize(HANDLE hProcess, SIZE_T dwMinimumWorkingSetSize,
									   SIZE_T dwMaximumWorkingSetSize) {
	DEBUG_LOG("SetProcessWorkingSetSize(%p, %zu, %zu)\n", hProcess, dwMinimumWorkingSetSize, dwMaximumWorkingSetSize);
	(void)hProcess;
	(void)dwMinimumWorkingSetSize;
	(void)dwMaximumWorkingSetSize;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

} // namespace kernel32
