#include <windows.h>

#include "test_assert.h"

static BOOL is_wine(void) {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	return ntdll != NULL && GetProcAddress(ntdll, "wine_get_version") != NULL;
}

int main(void) {
	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
	TEST_CHECK_MSG(kernel32 != NULL, "GetModuleHandleA(kernel32.dll) failed: %lu", (unsigned long)GetLastError());

	SetLastError(0xdeadbeef);
	FARPROC present = GetProcAddress(kernel32, "GetModuleHandleA");
	TEST_CHECK_MSG(present != NULL, "GetProcAddress(GetModuleHandleA) failed: %lu", (unsigned long)GetLastError());
	FARPROC formatMessage = GetProcAddress(kernel32, "FormatMessageA");
	TEST_CHECK_MSG(formatMessage != NULL, "GetProcAddress(FormatMessageA) failed: %lu", (unsigned long)GetLastError());

	SetLastError(0xdeadbeef);
	FARPROC missing = GetProcAddress(kernel32, "IsTNT");
	TEST_CHECK(missing == NULL);
	TEST_CHECK_EQ(ERROR_PROC_NOT_FOUND, GetLastError());

	if (!is_wine()) {
		HMODULE lmgr = LoadLibraryA("lmgr11.dll");
		TEST_CHECK_MSG(lmgr != NULL, "LoadLibraryA(lmgr11.dll) failed: %lu", (unsigned long)GetLastError());

		FARPROC missingOrdinal = GetProcAddress(lmgr, (LPCSTR)191);
		TEST_CHECK_MSG(missingOrdinal != NULL, "GetProcAddress(lmgr11.dll, 191) failed: %lu",
					   (unsigned long)GetLastError());
		FARPROC missingName = GetProcAddress(lmgr, "missing_for_test");
		TEST_CHECK_MSG(missingName != NULL, "GetProcAddress(lmgr11.dll, missing_for_test) failed: %lu",
					   (unsigned long)GetLastError());
	}

	return 0;
}
