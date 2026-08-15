#include <stdint.h>
#include <stdlib.h>
#include <windows.h>

#include "test_assert.h"

static uint16_t g_x87ControlWord;
static uint32_t g_mxcsr;
static uint16_t g_threadX87ControlWord;
static uint32_t g_threadMxcsr;

static void NTAPI capture_fpu_state(PVOID module, DWORD reason, PVOID reserved) {
	(void)module;
	(void)reserved;
	if (reason != DLL_PROCESS_ATTACH) {
		return;
	}
	__asm__ volatile("fnstcw %0" : "=m"(g_x87ControlWord));
	__asm__ volatile("stmxcsr %0" : "=m"(g_mxcsr));
}

PIMAGE_TLS_CALLBACK g_fpuStateCallback __attribute__((section(".CRT$XLB"), used)) = capture_fpu_state;

static DWORD WINAPI capture_thread_fpu_state(LPVOID param) {
	(void)param;
	__asm__ volatile("fnstcw %0" : "=m"(g_threadX87ControlWord));
	__asm__ volatile("stmxcsr %0" : "=m"(g_threadMxcsr));
	return 0;
}

int main(void) {
	TEST_CHECK_EQ(0x027f, g_x87ControlWord);
	// Exception status flags may be raised before the process-attach callback runs.
	TEST_CHECK_EQ(0x1f80, g_mxcsr & ~0x3f);

	HANDLE thread = CreateThread(NULL, 0, capture_thread_fpu_state, NULL, 0, NULL);
	TEST_CHECK(thread != NULL);
	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(thread, INFINITE));
	TEST_CHECK(CloseHandle(thread));
	TEST_CHECK_EQ(0x027f, g_threadX87ControlWord);
	TEST_CHECK_EQ(0x1f80, g_threadMxcsr & ~0x3f);
	return EXIT_SUCCESS;
}
