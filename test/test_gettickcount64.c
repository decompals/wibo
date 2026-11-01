#include "test_assert.h"

#include <windows.h>

int main(void) {
	ULONGLONG first = GetTickCount64();
	Sleep(60);
	ULONGLONG second = GetTickCount64();
	TEST_CHECK(second >= first + 40);
	TEST_CHECK(second < first + 5000);

	DWORD low = GetTickCount();
	ULONGLONG full = GetTickCount64();
	TEST_CHECK((DWORD)((DWORD)full - low) < 1000);
	return 0;
}
