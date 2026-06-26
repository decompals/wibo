#include "test_assert.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

static const char *basename_of(const char *path) {
	const char *slash = strrchr(path, '\\');
	return slash ? slash + 1 : path;
}

static void expect_fixed_unique_name(const char *temp_path) {
	char temp_file[MAX_PATH];

	UINT result = GetTempFileNameA(temp_path, "wboX", 0x12345, temp_file);
	TEST_CHECK_EQ(0x12345, result);
	DeleteFileA(temp_file);

	result = GetTempFileNameA(temp_path, "wboX", 0x12345, temp_file);
	TEST_CHECK_EQ(0x12345, result);
	TEST_CHECK_STR_EQ("wbo2345.TMP", basename_of(temp_file));
	TEST_CHECK_EQ(INVALID_FILE_ATTRIBUTES, GetFileAttributesA(temp_file));
}

static void expect_created_file_reopens_like_link(const char *temp_path) {
	char temp_file[MAX_PATH];

	UINT result = GetTempFileNameA(temp_path, "GDI32", 0, temp_file);
	TEST_CHECK(result != 0);
	TEST_CHECK_EQ(11, strlen(basename_of(temp_file)));
	TEST_CHECK_EQ(0, strncmp("GDI", basename_of(temp_file), 3));
	TEST_CHECK_STR_EQ(".TMP", basename_of(temp_file) + 7);
	TEST_CHECK(GetFileAttributesA(temp_file) != INVALID_FILE_ATTRIBUTES);

	HANDLE handle = CreateFileA(temp_file, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
								FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
	TEST_CHECK_MSG(handle != INVALID_HANDLE_VALUE, "CreateFileA(temp, OPEN_EXISTING|DELETE_ON_CLOSE) failed: %lu",
				   GetLastError());
	TEST_CHECK(CloseHandle(handle));
}

int main(void) {
	char temp_path[MAX_PATH];
	DWORD len = GetTempPathA(sizeof(temp_path), temp_path);
	TEST_CHECK(len > 0 && len < sizeof(temp_path));

	expect_fixed_unique_name(temp_path);
	expect_created_file_reopens_like_link(temp_path);

	return 0;
}
