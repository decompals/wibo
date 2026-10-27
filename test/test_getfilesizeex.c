#include <windows.h>

#include "test_assert.h"

static const char kFileName[] = "test_getfilesizeex.tmp";

int main(void) {
	TEST_CHECK(AreFileApisANSI());

	HANDLE file = CreateFileA(kFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
							  FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
	TEST_CHECK_MSG(file != INVALID_HANDLE_VALUE, "CreateFileA failed: %lu", GetLastError());

	LARGE_INTEGER size;
	size.QuadPart = -1;
	TEST_CHECK_MSG(GetFileSizeEx(file, &size), "GetFileSizeEx failed: %lu", GetLastError());
	TEST_CHECK_U64_EQ(0ull, (unsigned long long)size.QuadPart);

	const char payload[] = "wibo";
	DWORD written = 0;
	TEST_CHECK(WriteFile(file, payload, sizeof(payload), &written, NULL));
	TEST_CHECK_EQ(sizeof(payload), written);

	TEST_CHECK(GetFileSizeEx(file, &size));
	TEST_CHECK_U64_EQ((unsigned long long)sizeof(payload), (unsigned long long)size.QuadPart);

	SetLastError(0xdeadbeef);
	TEST_CHECK(!GetFileSizeEx(INVALID_HANDLE_VALUE, &size));
	TEST_CHECK_EQ(ERROR_INVALID_HANDLE, GetLastError());

	TEST_CHECK(CloseHandle(file));
	return 0;
}
