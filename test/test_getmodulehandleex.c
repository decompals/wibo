#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "test_assert.h"

static int g_address_probe;

int main(void) {
	HMODULE processModule = GetModuleHandleW(NULL);
	TEST_CHECK_MSG(processModule != NULL, "GetModuleHandleW(NULL) failed: %lu", (unsigned long)GetLastError());

	HMODULE module = (HMODULE)(ULONG_PTR)0x12345678;
	SetLastError(0xdeadbeef);
	TEST_CHECK_MSG(GetModuleHandleExW(0, NULL, &module), "GetModuleHandleExW(NULL) failed: %lu",
				   (unsigned long)GetLastError());
	TEST_CHECK_EQ((ULONG_PTR)processModule, (ULONG_PTR)module);

	HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
	TEST_CHECK_MSG(kernel32 != NULL, "GetModuleHandleW(kernel32.dll) failed: %lu", (unsigned long)GetLastError());
	module = NULL;
	TEST_CHECK_MSG(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, L"kernel32.dll", &module),
				   "GetModuleHandleExW(kernel32.dll) failed: %lu", (unsigned long)GetLastError());
	TEST_CHECK_EQ((ULONG_PTR)kernel32, (ULONG_PTR)module);

	module = NULL;
	TEST_CHECK_MSG(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN, L"kernel32.dll", &module),
				   "GetModuleHandleExW(PIN) failed: %lu", (unsigned long)GetLastError());
	TEST_CHECK_EQ((ULONG_PTR)kernel32, (ULONG_PTR)module);

	module = NULL;
	TEST_CHECK_MSG(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)&g_address_probe, &module),
				   "GetModuleHandleExW(FROM_ADDRESS) failed: %lu", (unsigned long)GetLastError());
	TEST_CHECK_EQ((ULONG_PTR)processModule, (ULONG_PTR)module);

	module = (HMODULE)(ULONG_PTR)0x12345678;
	SetLastError(0xdeadbeef);
	TEST_CHECK(!GetModuleHandleExW(0, L"definitely_missing_wibo_test.dll", &module));
	TEST_CHECK_EQ(0, (ULONG_PTR)module);
	TEST_CHECK_EQ(ERROR_MOD_NOT_FOUND, GetLastError());

	SetLastError(0xdeadbeef);
	TEST_CHECK(!GetModuleHandleExW(0, NULL, NULL));
	TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());

	module = (HMODULE)(ULONG_PTR)0x12345678;
	SetLastError(0xdeadbeef);
	TEST_CHECK(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
								   L"kernel32.dll", &module));
	TEST_CHECK_EQ(0, (ULONG_PTR)module);
	TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());

	return 0;
}
