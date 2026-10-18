#include "test_assert.h"

#include <string.h>
#include <wchar.h>
#include <windows.h>

int main(void) {
	char buffer[MAX_PATH];
	DWORD len = GetTempPathA(sizeof(buffer), buffer);
	TEST_CHECK(len > 0 && len < sizeof(buffer));
	TEST_CHECK_EQ(len, strlen(buffer));
	TEST_CHECK_EQ('\\', buffer[len - 1]);

	char too_small[MAX_PATH];
	memset(too_small, 0xCC, sizeof(too_small));
	SetLastError(0x12345678);
	DWORD required = GetTempPathA(len, too_small);
	TEST_CHECK_EQ(len + 1, required);
	TEST_CHECK_EQ(0x12345678, GetLastError());
	TEST_CHECK_EQ(0xCC, (unsigned char)too_small[len]);
	TEST_CHECK_EQ(len + 1, GetTempPathA(0, NULL));
	TEST_CHECK_EQ(0x12345678, GetLastError());

	required = GetTempPathA(len + 1, buffer);
	TEST_CHECK_EQ(len, required);
	TEST_CHECK_EQ(0, buffer[len]);

	WCHAR wide_buffer[MAX_PATH];
	DWORD wide_len = GetTempPathW(MAX_PATH, wide_buffer);
	TEST_CHECK(wide_len > 0 && wide_len < MAX_PATH);
	TEST_CHECK_EQ(wide_len, wcslen(wide_buffer));
	TEST_CHECK_EQ('\\', wide_buffer[wide_len - 1]);

	WCHAR wide_too_small[MAX_PATH];
	memset(wide_too_small, 0xCC, sizeof(wide_too_small));
	SetLastError(0x12345678);
	required = GetTempPathW(wide_len, wide_too_small);
	TEST_CHECK_EQ(wide_len + 1, required);
	TEST_CHECK_EQ(0x12345678, GetLastError());
	TEST_CHECK_EQ(0xCCCC, wide_too_small[wide_len]);
	TEST_CHECK_EQ(wide_len + 1, GetTempPathW(0, NULL));
	TEST_CHECK_EQ(0x12345678, GetLastError());

	required = GetTempPathW(wide_len + 1, wide_buffer);
	TEST_CHECK_EQ(wide_len, required);
	TEST_CHECK_EQ(0, wide_buffer[wide_len]);

	return 0;
}
