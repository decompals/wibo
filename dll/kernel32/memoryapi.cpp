#include "memoryapi.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "handles.h"
#include "heap.h"
#include "internal.h"
#include "strutil.h"
#include "types.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iterator>
#include <limits>
#include <map>
#include <mutex>
#include <sys/mman.h>
#include <unistd.h>
#include <utility>

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
	bool managed = false;
};

std::map<uintptr_t, ViewInfo> g_viewInfo;
std::mutex g_viewInfoMutex;

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

bool mappedViewRegionForAddress(uintptr_t request, uintptr_t pageBase, MEMORY_BASIC_INFORMATION &info) {
	std::lock_guard guard(g_viewInfoMutex);
	if (g_viewInfo.empty()) {
		return false;
	}
	const size_t pageSize = wibo::heap::systemPageSize();
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
		info.BaseAddress = toGuestPtr(reinterpret_cast<void *>(blockStart));
		info.AllocationBase = toGuestPtr(reinterpret_cast<void *>(view.viewBase));
		info.AllocationProtect = view.allocationProtect;
		info.RegionSize = blockEnd > blockStart ? blockEnd - blockStart : 0;
		info.State = MEM_COMMIT;
		info.Protect = view.protect;
		info.Type = view.type;
		return true;
	}
	return false;
}

} // namespace

namespace kernel32 {

HANDLE WINAPI CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect,
								 DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CreateFileMappingA(%p, %p, %u, %u, %u, %s)\n", hFile, lpFileMappingAttributes, flProtect,
			  dwMaximumSizeHigh, dwMaximumSizeLow, lpName ? lpName : "(null)");
	(void)lpFileMappingAttributes;
	(void)lpName;

	uint64_t size = (static_cast<uint64_t>(dwMaximumSizeHigh) << 32) | dwMaximumSizeLow;
	if (flProtect != PAGE_READONLY && flProtect != PAGE_READWRITE && flProtect != PAGE_WRITECOPY) {
		DEBUG_LOG("CreateFileMappingA: unsupported protection 0x%x\n", flProtect);
		setLastError(ERROR_INVALID_PARAMETER);
		return NO_HANDLE;
	}

	auto mapping = make_pin<MappingObject>();
	mapping->protect = flProtect;

	if (hFile == INVALID_HANDLE_VALUE) {
		mapping->anonymous = true;
		mapping->fd = -1;
		if (size == 0) {
			setLastError(ERROR_INVALID_PARAMETER);
			return NO_HANDLE;
		}
		mapping->maxSize = size;
	} else {
		auto file = wibo::handles().getAs<FileObject>(hFile);
		if (!file || !file->valid()) {
			setLastError(ERROR_INVALID_HANDLE);
			return NO_HANDLE;
		}
		int dupFd = fcntl(file->fd, F_DUPFD_CLOEXEC, 0);
		if (dupFd == -1) {
			setLastErrorFromErrno();
			return NO_HANDLE;
		}
		mapping->fd = dupFd;
		if (size == 0) {
			off_t fileSize = lseek(dupFd, 0, SEEK_END);
			if (fileSize < 0) {
				return NO_HANDLE;
			}
			size = static_cast<uint64_t>(fileSize);
		}
		mapping->maxSize = size;
	}

	return wibo::handles().alloc(std::move(mapping), 0, 0);
}

HANDLE WINAPI CreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect,
								 DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CreateFileMappingW -> ");
	std::string name = wideStringToString(lpName);
	return CreateFileMappingA(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow,
							  lpName ? name.c_str() : nullptr);
}

static LPVOID mapViewOfFileInternal(Pin<MappingObject> mapping, DWORD dwDesiredAccess, uint64_t offset,
									SIZE_T dwNumberOfBytesToMap, LPVOID baseAddress) {
	if (!mapping) {
		setLastError(ERROR_INVALID_HANDLE);
		return nullptr;
	}
	if (mapping->closed) {
		setLastError(ERROR_INVALID_HANDLE);
		return nullptr;
	}
	if (mapping->anonymous && offset != 0) {
		setLastError(ERROR_INVALID_PARAMETER);
		return nullptr;
	}
	size_t maxSize = mapping->maxSize;
	uint64_t length = static_cast<uint64_t>(dwNumberOfBytesToMap);
	if (length == 0) {
		if (maxSize == 0 || offset > maxSize) {
			setLastError(ERROR_INVALID_PARAMETER);
			return nullptr;
		}
		length = maxSize - offset;
	}
	if (length == 0) {
		setLastError(ERROR_INVALID_PARAMETER);
		return nullptr;
	}
	if (maxSize != 0 && offset + length > maxSize) {
		setLastError(ERROR_INVALID_PARAMETER);
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
			setLastError(ERROR_ACCESS_DENIED);
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
	const size_t pageSize = wibo::heap::systemPageSize();
	off_t alignedOffset = mapping->anonymous ? 0 : static_cast<off_t>(offset & ~static_cast<uint64_t>(pageSize - 1));
	size_t offsetDelta = static_cast<size_t>(offset - static_cast<uint64_t>(alignedOffset));
	uint64_t requestedLength = length + offsetDelta;
	if (requestedLength < length) {
		setLastError(ERROR_INVALID_PARAMETER);
		return nullptr;
	}
	size_t mapLength = static_cast<size_t>(requestedLength);
	if (static_cast<uint64_t>(mapLength) != requestedLength) {
		setLastError(ERROR_INVALID_PARAMETER);
		return nullptr;
	}

	int mmapFd = mapping->anonymous ? -1 : mapping->fd;
	void *requestedBase = nullptr;
	int mapFlags = flags;
	bool reservedMapping = false;
	if (baseAddress) {
		uintptr_t baseAddr = reinterpret_cast<uintptr_t>(baseAddress);
		if (baseAddr == 0 || (baseAddr % kVirtualAllocationGranularity) != 0) {
			setLastError(ERROR_INVALID_ADDRESS);
			return nullptr;
		}
		if (offsetDelta > baseAddr) {
			setLastError(ERROR_INVALID_ADDRESS);
			return nullptr;
		}
		uintptr_t mapBaseAddr = baseAddr - offsetDelta;
		if ((mapBaseAddr & (pageSize - 1)) != 0) {
			setLastError(ERROR_INVALID_ADDRESS);
			return nullptr;
		}
		requestedBase = reinterpret_cast<void *>(mapBaseAddr);
#ifdef MAP_FIXED_NOREPLACE
		mapFlags |= MAP_FIXED_NOREPLACE;
#else
		mapFlags |= MAP_FIXED;
#endif
	} else {
		void *candidate = nullptr;
		wibo::heap::VmStatus reserveStatus = wibo::heap::reserveViewRange(mapLength, 0, 0, &candidate);
		if (reserveStatus != wibo::heap::VmStatus::Success) {
			setLastError(wibo::heap::win32ErrorFromVmStatus(reserveStatus));
			return nullptr;
		}
		reservedMapping = true;
		requestedBase = candidate;
		mapFlags |= MAP_FIXED;
	}

	errno = 0;
	void *mapBase = mmap(requestedBase, mapLength, prot, mapFlags, mmapFd, alignedOffset);
	if (mapBase == MAP_FAILED) {
		int err = errno;
		if (baseAddress && (err == ENOMEM || err == EEXIST || err == EINVAL || err == EPERM)) {
			setLastError(ERROR_INVALID_ADDRESS);
		} else {
			setLastError(wibo::winErrorFromErrno(err));
		}
		if (reservedMapping) {
			wibo::heap::releaseViewRange(requestedBase);
		}
		return nullptr;
	}
	void *viewPtr = static_cast<uint8_t *>(mapBase) + offsetDelta;
	if (baseAddress && viewPtr != baseAddress) {
		munmap(mapBase, mapLength);
		setLastError(ERROR_INVALID_ADDRESS);
		if (reservedMapping) {
			wibo::heap::releaseViewRange(requestedBase);
		}
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
	view.managed = reservedMapping;
	if (reservedMapping) {
		wibo::heap::registerViewRange(mapBase, mapLength, protect, view.protect);
	}
	{
		std::lock_guard guard(g_viewInfoMutex);
		g_viewInfo.emplace(view.viewBase, std::move(view));
	}
	return viewPtr;
}

LPVOID WINAPI MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh,
							DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("MapViewOfFile(%p, 0x%x, %u, %u, %zu)\n", hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh,
			  dwFileOffsetLow, dwNumberOfBytesToMap);

	auto mapping = wibo::handles().getAs<MappingObject>(hFileMappingObject);
	if (!mapping) {
		setLastError(ERROR_INVALID_HANDLE);
		return nullptr;
	}
	uint64_t offset = (static_cast<uint64_t>(dwFileOffsetHigh) << 32) | dwFileOffsetLow;
	return mapViewOfFileInternal(std::move(mapping), dwDesiredAccess, offset, dwNumberOfBytesToMap, nullptr);
}

LPVOID WINAPI MapViewOfFileEx(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh,
							  DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("MapViewOfFileEx(%p, 0x%x, %u, %u, %zu, %p)\n", hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh,
			  dwFileOffsetLow, dwNumberOfBytesToMap, lpBaseAddress);

	auto mapping = wibo::handles().getAs<MappingObject>(hFileMappingObject);
	if (!mapping) {
		setLastError(ERROR_INVALID_HANDLE);
		return nullptr;
	}
	uint64_t offset = (static_cast<uint64_t>(dwFileOffsetHigh) << 32) | dwFileOffsetLow;
	return mapViewOfFileInternal(std::move(mapping), dwDesiredAccess, offset, dwNumberOfBytesToMap, lpBaseAddress);
}

BOOL WINAPI UnmapViewOfFile(LPCVOID lpBaseAddress) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("UnmapViewOfFile(%p)\n", lpBaseAddress);
	std::unique_lock lk(g_viewInfoMutex);
	auto it = g_viewInfo.find(reinterpret_cast<uintptr_t>(lpBaseAddress));
	if (it == g_viewInfo.end()) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	void *base = reinterpret_cast<void *>(it->second.allocationBase);
	size_t length = it->second.allocationLength;
	bool managed = it->second.managed;
	g_viewInfo.erase(it);
	lk.unlock();
	if (length != 0) {
		munmap(base, length);
	}
	if (managed) {
		wibo::heap::releaseViewRange(base);
	}
	return TRUE;
}

BOOL WINAPI FlushViewOfFile(LPCVOID lpBaseAddress, SIZE_T dwNumberOfBytesToFlush) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FlushViewOfFile(%p, %zu)\n", lpBaseAddress, dwNumberOfBytesToFlush);

	if (!lpBaseAddress) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	uintptr_t address = reinterpret_cast<uintptr_t>(lpBaseAddress);
	uintptr_t viewBase = 0;
	size_t viewLength = 0;
	uintptr_t allocationBase = 0;
	size_t allocationLength = 0;

	{
		std::lock_guard guard(g_viewInfoMutex);
		auto it = g_viewInfo.upper_bound(address);
		if (it == g_viewInfo.begin()) {
			setLastError(ERROR_INVALID_PARAMETER);
			return FALSE;
		}
		--it;
		const auto &view = it->second;
		if (address < view.viewBase || address >= view.viewBase + view.viewLength) {
			setLastError(ERROR_INVALID_PARAMETER);
			return FALSE;
		}
		viewBase = view.viewBase;
		viewLength = view.viewLength;
		allocationBase = view.allocationBase;
		allocationLength = view.allocationLength;
	}

	size_t offsetIntoView = static_cast<size_t>(address - viewBase);
	size_t bytesToFlush = dwNumberOfBytesToFlush;
	size_t maxFlush = viewLength - offsetIntoView;
	if (bytesToFlush == 0 || bytesToFlush > maxFlush) {
		bytesToFlush = maxFlush;
	}
	if (bytesToFlush == 0) {
		return TRUE;
	}

	uintptr_t flushStart = address;
	uintptr_t flushEnd = flushStart + bytesToFlush;
	const size_t pageSize = wibo::heap::systemPageSize();
	uintptr_t alignedStart = alignDown(flushStart, pageSize);
	uintptr_t alignedEnd = alignUp(flushEnd, pageSize);
	if (alignedEnd == std::numeric_limits<uintptr_t>::max()) {
		alignedEnd = flushEnd;
	}

	uintptr_t mappingEnd = allocationBase + allocationLength;
	if (alignedEnd > mappingEnd) {
		alignedEnd = mappingEnd;
	}
	if (alignedEnd < alignedStart) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	size_t length = static_cast<size_t>(alignedEnd - alignedStart);
	if (length == 0) {
		length = pageSize;
	}

	if (msync(reinterpret_cast<void *>(alignedStart), length, MS_SYNC) != 0) {
		setLastError(wibo::winErrorFromErrno(errno));
		return FALSE;
	}

	return TRUE;
}

LPVOID WINAPI VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("VirtualAlloc(%p, %zu, %u, %u)\n", lpAddress, dwSize, flAllocationType, flProtect);

	void *base = lpAddress;
	std::size_t size = static_cast<std::size_t>(dwSize);
	wibo::heap::VmStatus status = wibo::heap::virtualAlloc(&base, &size, flAllocationType, flProtect);
	if (status != wibo::heap::VmStatus::Success) {
		DWORD err = wibo::heap::win32ErrorFromVmStatus(status);
		DEBUG_LOG("-> failed (status=%u, err=%u)\n", static_cast<unsigned>(status), err);
		setLastError(err);
		return nullptr;
	}
	DEBUG_LOG("-> success (base=%p, size=%zu)\n", base, size);
	return base;
}

BOOL WINAPI VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("VirtualFree(%p, %zu, %u)\n", lpAddress, dwSize, dwFreeType);
	wibo::heap::VmStatus status = wibo::heap::virtualFree(lpAddress, static_cast<std::size_t>(dwSize), dwFreeType);
	if (status != wibo::heap::VmStatus::Success) {
		DWORD err = wibo::heap::win32ErrorFromVmStatus(status);
		DEBUG_LOG("-> failed (status=%u, err=%u)\n", static_cast<unsigned>(status), err);
		setLastError(err);
		return FALSE;
	}
	return TRUE;
}

BOOL WINAPI VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("VirtualProtect(%p, %zu, %u)\n", lpAddress, dwSize, flNewProtect);
	wibo::heap::VmStatus status =
		wibo::heap::virtualProtect(lpAddress, static_cast<std::size_t>(dwSize), flNewProtect, lpflOldProtect);
	if (status != wibo::heap::VmStatus::Success) {
		DWORD err = wibo::heap::win32ErrorFromVmStatus(status);
		DEBUG_LOG("-> failed (status=%u, err=%u)\n", static_cast<unsigned>(status), err);
		setLastError(err);
		return FALSE;
	}
	return TRUE;
}

SIZE_T WINAPI VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("VirtualQuery(%p, %p, %zu)\n", lpAddress, lpBuffer, dwLength);
	if (!lpBuffer || dwLength < sizeof(MEMORY_BASIC_INFORMATION)) {
		setLastError(ERROR_INVALID_PARAMETER);
		DEBUG_LOG("-> ERROR_INVALID_PARAMETER\n");
		return 0;
	}

	std::memset(lpBuffer, 0, sizeof(MEMORY_BASIC_INFORMATION));
	const size_t pageSize = wibo::heap::systemPageSize();
	uintptr_t request = lpAddress ? reinterpret_cast<uintptr_t>(lpAddress) : 0;
	uintptr_t pageBase = alignDown(request, pageSize);
	if (pageBase >= kProcessAddressLimit) {
		setLastError(ERROR_INVALID_PARAMETER);
		DEBUG_LOG("-> ERROR_INVALID_PARAMETER (beyond address space)\n");
		return 0;
	}

	MEMORY_BASIC_INFORMATION info{};
	if (mappedViewRegionForAddress(request, pageBase, info)) {
		*lpBuffer = info;
		return sizeof(MEMORY_BASIC_INFORMATION);
	}

	wibo::heap::VmStatus status = wibo::heap::virtualQuery(lpAddress, &info);
	if (status == wibo::heap::VmStatus::Success) {
		*lpBuffer = info;
		return sizeof(MEMORY_BASIC_INFORMATION);
	}

	DEBUG_LOG("VirtualQuery fallback failed status=%u\n", static_cast<unsigned>(status));
	setLastError(wibo::heap::win32ErrorFromVmStatus(status));
	DEBUG_LOG("-> VirtualQuery failed (status=%u)\n", static_cast<unsigned>(status));
	return 0;
}

BOOL WINAPI GetProcessWorkingSetSize(HANDLE hProcess, PSIZE_T lpMinimumWorkingSetSize,
									 PSIZE_T lpMaximumWorkingSetSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetProcessWorkingSetSize(%p, %p, %p)\n", hProcess, lpMinimumWorkingSetSize, lpMaximumWorkingSetSize);
	(void)hProcess;
	if (!lpMinimumWorkingSetSize || !lpMaximumWorkingSetSize) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	*lpMinimumWorkingSetSize = 32 * 1024 * 1024;  // 32 MiB stub
	*lpMaximumWorkingSetSize = 128 * 1024 * 1024; // 128 MiB stub
	return TRUE;
}

BOOL WINAPI SetProcessWorkingSetSize(HANDLE hProcess, SIZE_T dwMinimumWorkingSetSize, SIZE_T dwMaximumWorkingSetSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetProcessWorkingSetSize(%p, %zu, %zu)\n", hProcess, dwMinimumWorkingSetSize, dwMaximumWorkingSetSize);
	(void)hProcess;
	(void)dwMinimumWorkingSetSize;
	(void)dwMaximumWorkingSetSize;
	return TRUE;
}

} // namespace kernel32
