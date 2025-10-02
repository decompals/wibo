#include "heapapi.h"
#include "common.h"
#include "errors.h"
#include "handles.h"
#include "internal.h"

#include <algorithm>
#include <mimalloc.h>
#include <mutex>
#include <new>
#include <sys/mman.h>

namespace {

struct HeapRecord {
	mi_heap_t *heap = nullptr;
	DWORD createFlags = 0;
	SIZE_T initialSize = 0;
	SIZE_T maximumSize = 0;
	DWORD compatibility = 0;
	bool isProcessHeap = false;
};

std::once_flag g_processHeapInitFlag;
HANDLE g_processHeapHandle = nullptr;
HeapRecord *g_processHeapRecord = nullptr;

void ensureProcessHeapInitialized() {
	std::call_once(g_processHeapInitFlag, []() {
		mi_heap_t *heap = mi_heap_get_default();
		auto *record = new (std::nothrow) HeapRecord{};
		if (!record) {
			return;
		}
		record->heap = heap;
		record->isProcessHeap = true;
		g_processHeapRecord = record;
		g_processHeapHandle = handles::allocDataHandle({handles::TYPE_HEAP, record, 0});
	});
}

HeapRecord *activeHeapRecord(HANDLE hHeap) {
	if (!hHeap) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return nullptr;
	}
	ensureProcessHeapInitialized();
	auto data = handles::dataFromHandle(hHeap, false);
	if (data.type != handles::TYPE_HEAP || data.ptr == nullptr) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return nullptr;
	}
	wibo::lastError = ERROR_SUCCESS;
	return static_cast<HeapRecord *>(data.ptr);
}

HeapRecord *popHeapRecord(HANDLE hHeap) {
	ensureProcessHeapInitialized();
	auto preview = handles::dataFromHandle(hHeap, false);
	if (preview.type != handles::TYPE_HEAP || preview.ptr == nullptr) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return nullptr;
	}
	auto data = handles::dataFromHandle(hHeap, true);
	wibo::lastError = ERROR_SUCCESS;
	return static_cast<HeapRecord *>(data.ptr);
}

bool isExecutableHeap(const HeapRecord *record) {
	return record && ((record->createFlags & HEAP_CREATE_ENABLE_EXECUTE) != 0);
}

LPVOID heapAllocFromRecord(HeapRecord *record, DWORD dwFlags, SIZE_T dwBytes) {
	if (!record) {
		return nullptr;
	}
	if ((record->createFlags | dwFlags) & HEAP_GENERATE_EXCEPTIONS) {
		DEBUG_LOG("HeapAlloc: HEAP_GENERATE_EXCEPTIONS not supported\n");
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}
	const bool zeroMemory = (dwFlags & HEAP_ZERO_MEMORY) != 0;
	const SIZE_T requestSize = std::max<SIZE_T>(1, dwBytes);
	void *mem = zeroMemory ? mi_heap_zalloc(record->heap, requestSize) : mi_heap_malloc(record->heap, requestSize);
	if (!mem) {
		wibo::lastError = ERROR_NOT_ENOUGH_MEMORY;
		return nullptr;
	}
	if (isExecutableHeap(record)) {
		kernel32::tryMarkExecutable(mem);
	}
	wibo::lastError = ERROR_SUCCESS;
	return mem;
}

} // namespace

namespace kernel32 {

HANDLE WIN_FUNC HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) {
	DEBUG_LOG("HeapCreate(%u, %zu, %zu)\n", flOptions, dwInitialSize, dwMaximumSize);
	if (dwMaximumSize != 0 && dwInitialSize > dwMaximumSize) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}

	mi_heap_t *heap = mi_heap_new();
	if (!heap) {
		wibo::lastError = ERROR_NOT_ENOUGH_MEMORY;
		return nullptr;
	}

	auto *record = new (std::nothrow) HeapRecord{};
	if (!record) {
		mi_heap_delete(heap);
		wibo::lastError = ERROR_NOT_ENOUGH_MEMORY;
		return nullptr;
	}

	record->heap = heap;
	record->createFlags = flOptions;
	record->initialSize = dwInitialSize;
	record->maximumSize = dwMaximumSize;
	record->isProcessHeap = false;

	HANDLE handle = handles::allocDataHandle({handles::TYPE_HEAP, record, 0});
	wibo::lastError = ERROR_SUCCESS;
	return handle;
}

BOOL WIN_FUNC HeapDestroy(HANDLE hHeap) {
	DEBUG_LOG("HeapDestroy(%p)\n", hHeap);
	HeapRecord *record = activeHeapRecord(hHeap);
	if (!record) {
		return FALSE;
	}
	if (record->isProcessHeap) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	record = popHeapRecord(hHeap);
	if (!record) {
		return FALSE;
	}
	mi_heap_destroy(record->heap);
	delete record;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

HANDLE WIN_FUNC GetProcessHeap() {
	ensureProcessHeapInitialized();
	wibo::lastError = ERROR_SUCCESS;
	DEBUG_LOG("GetProcessHeap() -> %p\n", g_processHeapHandle);
	return g_processHeapHandle;
}

BOOL WIN_FUNC HeapSetInformation(HANDLE HeapHandle, HEAP_INFORMATION_CLASS HeapInformationClass, PVOID HeapInformation,
								 SIZE_T HeapInformationLength) {
	DEBUG_LOG("HeapSetInformation(%p, %d, %p, %zu)\n", HeapHandle, static_cast<int>(HeapInformationClass),
			  HeapInformation, HeapInformationLength);
	ensureProcessHeapInitialized();
	switch (HeapInformationClass) {
	case HeapCompatibilityInformation: {
		if (!HeapInformation || HeapInformationLength < sizeof(ULONG)) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		HeapRecord *target = HeapHandle ? activeHeapRecord(HeapHandle) : g_processHeapRecord;
		if (!target) {
			return FALSE;
		}
		target->compatibility = *static_cast<ULONG *>(HeapInformation);
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	case HeapEnableTerminationOnCorruption:
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	case HeapOptimizeResources:
		wibo::lastError = ERROR_CALL_NOT_IMPLEMENTED;
		return FALSE;
	default:
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
}

LPVOID WIN_FUNC HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
	DEBUG_LOG("HeapAlloc(%p, 0x%x, %zu) ", hHeap, dwFlags, dwBytes);
	HeapRecord *record = activeHeapRecord(hHeap);
	if (!record) {
		DEBUG_LOG("-> NULL\n");
		return nullptr;
	}
	void *mem = heapAllocFromRecord(record, dwFlags, dwBytes);
	DEBUG_LOG("-> %p\n", mem);
	return mem;
}

LPVOID WIN_FUNC HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes) {
	DEBUG_LOG("HeapReAlloc(%p, 0x%x, %p, %zu) ", hHeap, dwFlags, lpMem, dwBytes);
	HeapRecord *record = activeHeapRecord(hHeap);
	if (!record) {
		DEBUG_LOG("-> NULL\n");
		return nullptr;
	}
	if (lpMem == nullptr) {
		void *alloc = heapAllocFromRecord(record, dwFlags, dwBytes);
		DEBUG_LOG("-> %p (alloc)\n", alloc);
		return alloc;
	}
	if (!mi_heap_check_owned(record->heap, lpMem)) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		DEBUG_LOG("-> NULL (not owned)\n");
		return nullptr;
	}
	if ((record->createFlags | dwFlags) & HEAP_GENERATE_EXCEPTIONS) {
		DEBUG_LOG("-> NULL (exceptions unsupported)\n");
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}
	const bool inplaceOnly = (dwFlags & HEAP_REALLOC_IN_PLACE_ONLY) != 0;
	const bool zeroMemory = (dwFlags & HEAP_ZERO_MEMORY) != 0;
	if (dwBytes == 0) {
		if (!inplaceOnly) {
			mi_free(lpMem);
			wibo::lastError = ERROR_SUCCESS;
			DEBUG_LOG("-> NULL (freed)\n");
			return nullptr;
		}
		wibo::lastError = ERROR_NOT_ENOUGH_MEMORY;
		DEBUG_LOG("-> NULL (zero size with in-place flag)\n");
		return nullptr;
	}

	const SIZE_T requestSize = std::max<SIZE_T>(1, dwBytes);
	const SIZE_T oldSize = mi_usable_size(lpMem);
	if (inplaceOnly || requestSize <= oldSize) {
		if (requestSize > oldSize) {
			wibo::lastError = ERROR_NOT_ENOUGH_MEMORY;
			DEBUG_LOG("-> NULL (cannot grow in place)\n");
			return nullptr;
		}
		wibo::lastError = ERROR_SUCCESS;
		DEBUG_LOG("-> %p (in-place)\n", lpMem);
		return lpMem;
	}

	void *ret = mi_heap_realloc(record->heap, lpMem, requestSize);
	if (!ret) {
		wibo::lastError = ERROR_NOT_ENOUGH_MEMORY;
		return nullptr;
	}
	if (zeroMemory && requestSize > oldSize) {
		size_t newUsable = mi_usable_size(ret);
		if (newUsable > oldSize) {
			size_t zeroLen = std::min<SIZE_T>(newUsable, requestSize) - oldSize;
			memset(static_cast<char *>(ret) + oldSize, 0, zeroLen);
		}
	}
	if (isExecutableHeap(record)) {
		tryMarkExecutable(ret);
	}
	wibo::lastError = ERROR_SUCCESS;
	DEBUG_LOG("-> %p\n", ret);
	return ret;
}

SIZE_T WIN_FUNC HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem) {
	DEBUG_LOG("HeapSize(%p, 0x%x, %p)\n", hHeap, dwFlags, lpMem);
	(void)dwFlags;
	HeapRecord *record = activeHeapRecord(hHeap);
	if (!record) {
		return static_cast<SIZE_T>(-1);
	}
	if (!lpMem) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return static_cast<SIZE_T>(-1);
	}
	if (!mi_heap_check_owned(record->heap, const_cast<LPVOID>(lpMem))) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return static_cast<SIZE_T>(-1);
	}
	size_t size = mi_usable_size(lpMem);
	wibo::lastError = ERROR_SUCCESS;
	return static_cast<SIZE_T>(size);
}

BOOL WIN_FUNC HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
	DEBUG_LOG("HeapFree(%p, 0x%x, %p)\n", hHeap, dwFlags, lpMem);
	(void)dwFlags;
	if (lpMem == nullptr) {
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	HeapRecord *record = activeHeapRecord(hHeap);
	if (!record) {
		return FALSE;
	}
	if (!mi_heap_check_owned(record->heap, lpMem)) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	mi_free(lpMem);
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

} // namespace kernel32
