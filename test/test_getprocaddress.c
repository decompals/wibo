#include <windows.h>

#include "test_assert.h"

int main(void) {
	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
	TEST_CHECK_MSG(kernel32 != NULL, "GetModuleHandleA(kernel32.dll) failed: %lu", (unsigned long)GetLastError());

	SetLastError(0xdeadbeef);
	FARPROC present = GetProcAddress(kernel32, "GetModuleHandleA");
	TEST_CHECK_MSG(present != NULL, "GetProcAddress(GetModuleHandleA) failed: %lu", (unsigned long)GetLastError());

	SetLastError(0xdeadbeef);
	FARPROC missing = GetProcAddress(kernel32, "IsTNT");
	TEST_CHECK(missing == NULL);
	TEST_CHECK_EQ(ERROR_PROC_NOT_FOUND, GetLastError());

	return 0;
}
