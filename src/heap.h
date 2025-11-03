#pragma once

#include "types.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>

struct mi_heap_s;
typedef struct mi_heap_s mi_heap_t;

namespace wibo::heap {

bool initialize();
uintptr_t systemPageSize();
uintptr_t allocationGranularity();
mi_heap_t *getGuestHeap();
mi_heap_t *createGuestHeap();

enum class VmStatus : uint32_t {
	Success = 0,
	InvalidParameter,
	InvalidAddress,
	NoAccess,
	NotSupported,
	NoMemory,
	Rejected,
	UnknownError,
};

// Guest heap memory allocation helpers
void *guestMalloc(std::size_t size);
void *guestCalloc(std::size_t count, std::size_t size);
void *guestRealloc(void *ptr, std::size_t newSize);
void guestFree(void *ptr);

VmStatus virtualAlloc(void **baseAddress, std::size_t *regionSize, DWORD allocationType, DWORD protect,
					  DWORD type = MEM_PRIVATE);
VmStatus virtualFree(void *baseAddress, std::size_t regionSize, DWORD freeType);
VmStatus virtualProtect(void *baseAddress, std::size_t regionSize, DWORD newProtect, DWORD *oldProtect);
VmStatus virtualQuery(const void *address, MEMORY_BASIC_INFORMATION *outInfo);
VmStatus virtualReset(void *baseAddress, std::size_t regionSize);

VmStatus reserveViewRange(std::size_t regionSize, uintptr_t minAddr, uintptr_t maxAddr, void **baseAddress);
void registerViewRange(void *baseAddress, std::size_t regionSize, DWORD allocationProtect, DWORD protect);
void releaseViewRange(void *baseAddress);

DWORD win32ErrorFromVmStatus(VmStatus status);
NTSTATUS ntStatusFromVmStatus(VmStatus status);

bool reserveGuestStack(std::size_t stackSizeBytes, void **outStackLimit, void **outStackBase);

} // namespace wibo::heap
