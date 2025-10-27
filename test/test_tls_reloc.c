#include "test_assert.h"
#include <stdint.h>
#include <windows.h>

#ifndef TLS_RELOC_PREFERRED_BASE
#define TLS_RELOC_PREFERRED_BASE 0x30000000u
#endif

#ifndef TLS_RELOC_INITIAL_VALUE
#define TLS_RELOC_INITIAL_VALUE 0x2468ACEDu
#endif

typedef int(__stdcall *tls_get_template_value_fn)(void);
typedef void *(__stdcall *tls_template_address_fn)(void);
typedef int(__stdcall *tls_callback_hits_fn)(void);
typedef DWORD(__stdcall *tls_module_index_fn)(void);

static void **module_tls_array(void) {
	void **ptr = NULL;
	__asm__ __volatile__("movl %%fs:0x2C, %0" : "=r"(ptr));
	return ptr;
}

typedef struct {
	tls_module_index_fn indexFn;
	tls_template_address_fn templateFn;
	tls_get_template_value_fn valueFn;
	HANDLE startEvent;
	void *observedPointer;
	intptr_t pointerOffset;
	int observedValue;
} WorkerCtx;

static DWORD WINAPI tls_worker_proc(LPVOID param) {
	WorkerCtx *ctx = (WorkerCtx *)param;
	TEST_CHECK(ctx != NULL);
	TEST_CHECK(ctx->startEvent != NULL);
	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(ctx->startEvent, 1000));
	TEST_CHECK(ctx->indexFn != NULL);
	TEST_CHECK(ctx->templateFn != NULL);

	DWORD moduleIndex = ctx->indexFn();
	void **tlsArray = module_tls_array();
	TEST_CHECK(tlsArray != NULL);
	void *threadSlot = tlsArray[moduleIndex];
	TEST_CHECK(threadSlot != NULL);
	void *expectedPtr = ctx->templateFn();
	ctx->observedPointer = threadSlot;
	ctx->pointerOffset = (intptr_t)((uint8_t *)expectedPtr - (uint8_t *)threadSlot);
	ctx->observedValue = ctx->valueFn ? ctx->valueFn() : *(int *)expectedPtr;

	return 0;
}

static void *reserve_preferred_region(size_t size) {
	void *preferred = (void *)(uintptr_t)TLS_RELOC_PREFERRED_BASE;
	void *reservation = VirtualAlloc(preferred, size, MEM_RESERVE, PAGE_NOACCESS);
	return reservation;
}

int main(void) {
	const size_t reservationSize = 0x200000; // 2 MB
	WorkerCtx workerCtx = {0};
	workerCtx.startEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
	TEST_CHECK(workerCtx.startEvent != NULL);

	HANDLE workerThread = CreateThread(NULL, 0, tls_worker_proc, &workerCtx, 0, NULL);
	TEST_CHECK(workerThread != NULL);

	void *preferred = (void *)(uintptr_t)TLS_RELOC_PREFERRED_BASE;
	void *reservation = reserve_preferred_region(reservationSize);
	TEST_CHECK_MSG(reservation == preferred, "VirtualAlloc(%p) failed: %lu", preferred, (unsigned long)GetLastError());

	HMODULE mod = LoadLibraryA("tls_reloc.dll");
	TEST_CHECK_MSG(mod != NULL, "LoadLibraryA failed: %lu", (unsigned long)GetLastError());

	TEST_CHECK_MSG(VirtualFree(reservation, 0, MEM_RELEASE) != 0, "VirtualFree failed: %lu",
				   (unsigned long)GetLastError());

	TEST_CHECK((uintptr_t)mod != (uintptr_t)preferred);

	FARPROC rawGet = GetProcAddress(mod, "tls_get_template_value@0");
	FARPROC rawAddr = GetProcAddress(mod, "tls_template_address@0");
	FARPROC rawHits = GetProcAddress(mod, "tls_callback_hits@0");
	FARPROC rawIndex = GetProcAddress(mod, "tls_module_index@0");
	TEST_CHECK(rawGet != NULL);
	TEST_CHECK(rawAddr != NULL);
	TEST_CHECK(rawHits != NULL);
	TEST_CHECK(rawIndex != NULL);

	tls_get_template_value_fn tls_get_template_value = (tls_get_template_value_fn)(uintptr_t)rawGet;
	tls_template_address_fn tls_template_address = (tls_template_address_fn)(uintptr_t)rawAddr;
	tls_callback_hits_fn tls_callback_hits = (tls_callback_hits_fn)(uintptr_t)rawHits;
	tls_module_index_fn tls_module_index = (tls_module_index_fn)(uintptr_t)rawIndex;

	workerCtx.indexFn = tls_module_index;
	workerCtx.templateFn = tls_template_address;
	workerCtx.valueFn = tls_get_template_value;
	TEST_CHECK(SetEvent(workerCtx.startEvent));

	void *templateAddr = tls_template_address();
	TEST_CHECK(templateAddr != NULL);

	int initial = tls_get_template_value();
	TEST_CHECK_EQ(TLS_RELOC_INITIAL_VALUE, (unsigned int)initial);

	DWORD moduleIndex = tls_module_index();
	void **tlsArray = module_tls_array();
	TEST_CHECK(tlsArray != NULL);
	void *mainThreadSlot = tlsArray[moduleIndex];
	TEST_CHECK(mainThreadSlot != NULL);

	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(workerThread, 1000));
	TEST_CHECK(workerCtx.observedPointer != NULL);
	TEST_CHECK(workerCtx.observedPointer != mainThreadSlot);
	intptr_t offset = (intptr_t)((uint8_t *)templateAddr - (uint8_t *)mainThreadSlot);
	int mainObserved = *(int *)((uint8_t *)mainThreadSlot + offset);
	TEST_CHECK_EQ((unsigned int)initial, (unsigned int)mainObserved);

	int originalValue = *(int *)templateAddr;
	int toggledValue = originalValue ^ 0x13572468;
	*(int *)templateAddr = toggledValue;
	TEST_CHECK_EQ((unsigned int)*(int *)templateAddr, (unsigned int)*(int *)((uint8_t *)mainThreadSlot + offset));
	*(int *)templateAddr = originalValue;
	int workerObserved = *(int *)((uint8_t *)workerCtx.observedPointer + workerCtx.pointerOffset);
	TEST_CHECK_EQ((unsigned int)workerCtx.observedValue, (unsigned int)workerObserved);

	int hits = tls_callback_hits();
	TEST_CHECK_EQ(1, hits);

	TEST_CHECK(FreeLibrary(mod));
	TEST_CHECK(CloseHandle(workerThread));
	TEST_CHECK(CloseHandle(workerCtx.startEvent));

	return EXIT_SUCCESS;
}
