#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include "test_assert.h"

static DWORD WINAPI workerProc(LPVOID param) {
	(void)param;
	return 0;
}

static FARPROC loadExport(HMODULE module, const char *name) {
	FARPROC proc = GetProcAddress(module, name);
#if defined(__i386__) || defined(_M_IX86)
	if (!proc) {
		char decorated[64];
		snprintf(decorated, sizeof(decorated), "_%s@0", name);
		proc = GetProcAddress(module, decorated);
	}
#endif
	return proc;
}

static BOOL isRunningUnderWine(void) {
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	return hNtdll != NULL && GetProcAddress(hNtdll, "wine_get_version") != NULL;
}

int main(void) {
	typedef LONG (*get_count_fn)(void);
	typedef void (*reset_counts_fn)(void);
	typedef BOOL (*disable_fn)(void);

	HMODULE mod = LoadLibraryA("thread_notifications.dll");
	TEST_CHECK_MSG(mod != NULL, "LoadLibraryA failed: %lu", (unsigned long)GetLastError());

	get_count_fn getAttach = (get_count_fn)(uintptr_t)loadExport(mod, "get_thread_attach_count");
	get_count_fn getDetach = (get_count_fn)(uintptr_t)loadExport(mod, "get_thread_detach_count");
	reset_counts_fn resetCounts = (reset_counts_fn)(uintptr_t)loadExport(mod, "reset_thread_counts");
	disable_fn disableNotifications = (disable_fn)(uintptr_t)loadExport(mod, "disable_thread_notifications");

	TEST_CHECK_MSG(getAttach != NULL, "Missing get_thread_attach_count: %lu", (unsigned long)GetLastError());
	TEST_CHECK_MSG(getDetach != NULL, "Missing get_thread_detach_count: %lu", (unsigned long)GetLastError());
	TEST_CHECK_MSG(resetCounts != NULL, "Missing reset_thread_counts: %lu", (unsigned long)GetLastError());
	TEST_CHECK_MSG(disableNotifications != NULL, "Missing disable_thread_notifications: %lu",
				   (unsigned long)GetLastError());

	resetCounts();
	TEST_CHECK_EQ(0, getAttach());
	TEST_CHECK_EQ(0, getDetach());

	HANDLE thread = CreateThread(NULL, 0, workerProc, NULL, 0, NULL);
	TEST_CHECK_MSG(thread != NULL, "CreateThread failed: %lu", (unsigned long)GetLastError());
	DWORD wait_result = WaitForSingleObject(thread, INFINITE);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait_result);
	TEST_CHECK_MSG(CloseHandle(thread) != 0, "CloseHandle(thread) failed: %lu", (unsigned long)GetLastError());

	TEST_CHECK_EQ(1, getAttach());
	TEST_CHECK_EQ(1, getDetach());

	resetCounts();

	// Wine throws ERR_MOD_NOT_FOUND from DisableThreadLibraryCalls, even if we pass in hinstDLL from DllMain
	// DLL_PROCESS_ATTACH, which is strange.
	TEST_CHECK_MSG(disableNotifications() || isRunningUnderWine(), "DisableThreadLibraryCalls failed: %lu",
				   (unsigned long)GetLastError());

	thread = CreateThread(NULL, 0, workerProc, NULL, 0, NULL);
	TEST_CHECK_MSG(thread != NULL, "CreateThread after disable failed: %lu", (unsigned long)GetLastError());
	wait_result = WaitForSingleObject(thread, INFINITE);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait_result);
	TEST_CHECK_MSG(CloseHandle(thread) != 0, "CloseHandle(second thread) failed: %lu", (unsigned long)GetLastError());

	if (!isRunningUnderWine()) {
		TEST_CHECK_EQ(0, getAttach());
		TEST_CHECK_EQ(0, getDetach());
	}

	LONG final_attach = getAttach();
	LONG final_detach = getDetach();

	TEST_CHECK_MSG(FreeLibrary(mod) != 0, "FreeLibrary failed: %lu", (unsigned long)GetLastError());

	printf("thread_notifications: attach=%ld detach=%ld\n", (long)final_attach, (long)final_detach);
	return EXIT_SUCCESS;
}
