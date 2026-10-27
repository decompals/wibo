#include <windows.h>

#include <stdio.h>

#include "test_assert.h"

static void check_volume_name(const WCHAR *name) {
	static const WCHAR kPrefix[] = L"\\\\?\\Volume{";
	size_t length = wcslen(name);
	TEST_CHECK_MSG(length > 10, "volume name too short (%zu)", length);
	TEST_CHECK(wcsncmp(name, kPrefix, 10) == 0);
	TEST_CHECK_MSG(name[length - 1] == L'\\', "volume name must end in a backslash");
}

static void test_enumerate_volumes(void) {
	WCHAR name[MAX_PATH];
	SetLastError(0xdeadbeef);
	HANDLE search = FindFirstVolumeW(name, MAX_PATH);
	TEST_CHECK_MSG(search != INVALID_HANDLE_VALUE, "FindFirstVolumeW failed: %lu", GetLastError());
	check_volume_name(name);

	int seen = 1;
	while (FindNextVolumeW(search, name, MAX_PATH)) {
		check_volume_name(name);
		TEST_CHECK_MSG(++seen < 1000, "FindNextVolumeW did not terminate");
	}
	TEST_CHECK_EQ(ERROR_NO_MORE_FILES, GetLastError());
	TEST_CHECK(FindVolumeClose(search));
}

static void test_buffer_too_small(void) {
	WCHAR name[4];
	SetLastError(0xdeadbeef);
	HANDLE search = FindFirstVolumeW(name, 4);
	TEST_CHECK(search == INVALID_HANDLE_VALUE);
	TEST_CHECK_EQ(ERROR_FILENAME_EXCED_RANGE, GetLastError());
}

int main(void) {
	test_enumerate_volumes();
	test_buffer_too_small();
	return 0;
}
