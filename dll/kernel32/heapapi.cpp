#include "heapapi.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "handles.h"
#include "internal.h"

#include <algorithm>
#include <mimalloc.h>
#include <mutex>
#include <sys/mman.h>

using kernel32::HeapObject;

namespace {

std::once_flag g_processHeapInitFlag;
HANDLE g_processHeapHandle = nullptr;
HeapObject *g_processHeapRecord = nullptr;

void ensureProcessHeapInitialized() {
	std::call_once(g_processHeapInitFlag, []() {
		mi_heap_t *heap = mi_heap_get_default();
		auto record = make_pin<HeapObject>(heap);
		if (!record) {
			return;
		}
		record->heap = heap;
		record->isProcessHeap = true;
		g_processHeapRecord = record.get();
		g_processHeapHandle = wibo::handles().alloc(std::move(record), 0, 0);
	});
}

bool isExecutableHeap(const HeapObject *record) {
	return record && ((record->createFlags & HEAP_CREATE_ENABLE_EXECUTE) != 0);
}

LPVOID heapAllocFromRecord(HeapObject *record, DWORD dwFlags, SIZE_T dwBytes) {
	if (!record || !record->heap) {
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
	return mem;
}

} // namespace

HeapObject::~HeapObject() {
	if (heap) {
		if (!isProcessHeap) {
			mi_heap_destroy(heap);
		}
		heap = nullptr;
	}
	if (isProcessHeap) {
		g_processHeapHandle = nullptr;
		g_processHeapRecord = nullptr;
	}
}

namespace kernel32 {

HANDLE WIN_FUNC HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) {
	HOST_CONTEXT_GUARD();
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

	auto record = make_pin<HeapObject>(heap);
	record->heap = heap;
	record->createFlags = flOptions;
	record->initialSize = dwInitialSize;
	record->maximumSize = dwMaximumSize;
	record->isProcessHeap = false;

	HANDLE handle = wibo::handles().alloc(std::move(record), 0, 0);
	return handle;
}

BOOL WIN_FUNC HeapDestroy(HANDLE hHeap) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("HeapDestroy(%p)\n", hHeap);
	auto record = wibo::handles().getAs<HeapObject>(hHeap);
	if (!record) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	std::lock_guard lk(record->m);
	if (record->isProcessHeap || record->heap == nullptr) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	mi_heap_destroy(record->heap);
	record->heap = nullptr;
	return TRUE;
}

HANDLE WIN_FUNC GetProcessHeap() {
	HOST_CONTEXT_GUARD();
	ensureProcessHeapInitialized();
	DEBUG_LOG("GetProcessHeap() -> %p\n", g_processHeapHandle);
	return g_processHeapHandle;
}

BOOL WIN_FUNC HeapSetInformation(HANDLE HeapHandle, HEAP_INFORMATION_CLASS HeapInformationClass, PVOID HeapInformation,
								 SIZE_T HeapInformationLength) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("HeapSetInformation(%p, %d, %p, %zu)\n", HeapHandle, static_cast<int>(HeapInformationClass),
			  HeapInformation, HeapInformationLength);
	auto record = wibo::handles().getAs<HeapObject>(HeapHandle);
	if (!record) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	std::lock_guard lk(record->m);
	if (!record->heap) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	switch (HeapInformationClass) {
	case HeapCompatibilityInformation: {
		if (!HeapInformation || HeapInformationLength < sizeof(ULONG)) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
		record->compatibility = *static_cast<ULONG *>(HeapInformation);
		return TRUE;
	}
	case HeapEnableTerminationOnCorruption:
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
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("HeapAlloc(%p, 0x%x, %zu) ", hHeap, dwFlags, dwBytes);
	auto record = wibo::handles().getAs<HeapObject>(hHeap);
	if (!record) {
		DEBUG_LOG("-> NULL\n");
		wibo::lastError = ERROR_INVALID_HANDLE;
		return nullptr;
	}
	std::lock_guard lk(record->m);
	if (!record->heap) {
		DEBUG_LOG("-> NULL\n");
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}
	void *mem = heapAllocFromRecord(record.get(), dwFlags, dwBytes);
	DEBUG_LOG("-> %p\n", mem);
	return mem;
}

LPVOID WIN_FUNC HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("HeapReAlloc(%p, 0x%x, %p, %zu) ", hHeap, dwFlags, lpMem, dwBytes);
	auto record = wibo::handles().getAs<HeapObject>(hHeap);
	if (!record) {
		DEBUG_LOG("-> NULL\n");
		wibo::lastError = ERROR_INVALID_HANDLE;
		return nullptr;
	}
	std::lock_guard lk(record->m);
	if (!record->heap) {
		DEBUG_LOG("-> NULL\n");
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return nullptr;
	}
	if (lpMem == nullptr) {
		void *alloc = heapAllocFromRecord(record.get(), dwFlags, dwBytes);
		DEBUG_LOG("-> %p (alloc)\n", alloc);
		return alloc;
	}
	// if (!mi_heap_check_owned(record->heap, lpMem)) {
	// 	DEBUG_LOG("-> NULL (not owned)\n");
	// 	wibo::lastError = ERROR_INVALID_PARAMETER;
	// 	return nullptr;
	// }
	if ((record->createFlags | dwFlags) & HEAP_GENERATE_EXCEPTIONS) {
		DEBUG_LOG("-> NULL (exceptions unsupported)\n");
		wibo::lastError = ERROR_NOT_SUPPORTED;
		return nullptr;
	}
	const bool inplaceOnly = (dwFlags & HEAP_REALLOC_IN_PLACE_ONLY) != 0;
	const bool zeroMemory = (dwFlags & HEAP_ZERO_MEMORY) != 0;
	if (dwBytes == 0) {
		if (!inplaceOnly) {
			mi_free(lpMem);
			DEBUG_LOG("-> NULL (freed)\n");
			return nullptr;
		}
		DEBUG_LOG("-> NULL (zero size with in-place flag)\n");
		wibo::lastError = ERROR_NOT_ENOUGH_MEMORY;
		return nullptr;
	}

	const SIZE_T requestSize = std::max<SIZE_T>(1, dwBytes);
	const SIZE_T oldSize = mi_usable_size(lpMem);
	if (inplaceOnly || requestSize <= oldSize) {
		if (requestSize > oldSize) {
			DEBUG_LOG("-> NULL (cannot grow in place)\n");
			wibo::lastError = ERROR_NOT_ENOUGH_MEMORY;
			return nullptr;
		}
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
	if (isExecutableHeap(record.get())) {
		tryMarkExecutable(ret);
	}
	DEBUG_LOG("-> %p\n", ret);
	return ret;
}

SIZE_T WIN_FUNC HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("HeapSize(%p, 0x%x, %p)\n", hHeap, dwFlags, lpMem);
	(void)dwFlags;
	auto record = wibo::handles().getAs<HeapObject>(hHeap);
	if (!record) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return static_cast<SIZE_T>(-1);
	}
	std::lock_guard lk(record->m);
	if (!record->heap) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return static_cast<SIZE_T>(-1);
	}
	if (!lpMem) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return static_cast<SIZE_T>(-1);
	}
	if (!mi_heap_check_owned(record->heap, const_cast<LPVOID>(lpMem))) {
		DEBUG_LOG("HeapSize: block %p not owned by heap %p\n", lpMem, record->heap);
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return static_cast<SIZE_T>(-1);
	}
	size_t size = mi_usable_size(lpMem);
	return static_cast<SIZE_T>(size);
}

BOOL WIN_FUNC HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("HeapFree(%p, 0x%x, %p)\n", hHeap, dwFlags, lpMem);
	(void)dwFlags;
	if (lpMem == nullptr) {
		return TRUE;
	}
	auto record = wibo::handles().getAs<HeapObject>(hHeap);
	if (!record) {
		DEBUG_LOG("-> INVALID_HANDLE\n");
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	std::lock_guard lk(record->m);
	if (!record->heap) {
		DEBUG_LOG("-> INVALID_PARAMETER\n");
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	if (!mi_heap_check_owned(record->heap, lpMem)) {
		DEBUG_LOG("-> INVALID_PARAMETER (not owned)\n");
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	mi_free(lpMem);
	DEBUG_LOG("-> SUCCESS\n");
	return TRUE;
}

} // namespace kernel32
