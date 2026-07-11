#include "test_assert.h"

#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

static const char *basename_of(const char *path) {
	const char *slash = strrchr(path, '\\');
	return slash ? slash + 1 : path;
}

static const WCHAR *basename_of_w(const WCHAR *path) {
	const WCHAR *slash = wcsrchr(path, L'\\');
	return slash ? slash + 1 : path;
}

static void expect_fixed_unique_name(const char *temp_path) {
	char temp_file[MAX_PATH];

	UINT result = GetTempFileNameA(temp_path, "wboX", 0x12345, temp_file);
	TEST_CHECK_EQ(0x2345, result);
	DeleteFileA(temp_file);

	result = GetTempFileNameA(temp_path, "wboX", 0x12345, temp_file);
	TEST_CHECK_EQ(0x2345, result);
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

static void expect_null_prefix_is_empty(const char *temp_path) {
	char temp_file[MAX_PATH];

	UINT result = GetTempFileNameA(temp_path, NULL, 0x12345, temp_file);
	TEST_CHECK_EQ(0x2345, result);
	TEST_CHECK_STR_EQ("2345.TMP", basename_of(temp_file));
}

static void expect_fixed_unique_name_w(const WCHAR *temp_path) {
	WCHAR temp_file[MAX_PATH];

	UINT result = GetTempFileNameW(temp_path, L"wboX", 0x12345, temp_file);
	TEST_CHECK_EQ(0x2345, result);
	DeleteFileW(temp_file);

	result = GetTempFileNameW(temp_path, L"wboX", 0x12345, temp_file);
	TEST_CHECK_EQ(0x2345, result);
	TEST_CHECK(wcscmp(L"wbo2345.TMP", basename_of_w(temp_file)) == 0);
	TEST_CHECK_EQ(INVALID_FILE_ATTRIBUTES, GetFileAttributesW(temp_file));
}

static void expect_created_file_reopens_like_link_w(const WCHAR *temp_path) {
	WCHAR temp_file[MAX_PATH];

	UINT result = GetTempFileNameW(temp_path, L"GDI32", 0, temp_file);
	TEST_CHECK(result != 0);
	TEST_CHECK_EQ(11, wcslen(basename_of_w(temp_file)));
	TEST_CHECK_EQ(0, wcsncmp(L"GDI", basename_of_w(temp_file), 3));
	TEST_CHECK(wcscmp(L".TMP", basename_of_w(temp_file) + 7) == 0);
	TEST_CHECK(GetFileAttributesW(temp_file) != INVALID_FILE_ATTRIBUTES);

	HANDLE handle = CreateFileW(temp_file, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
								FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
	TEST_CHECK_MSG(handle != INVALID_HANDLE_VALUE, "CreateFileW(temp, OPEN_EXISTING|DELETE_ON_CLOSE) failed: %lu",
				   GetLastError());
	TEST_CHECK(CloseHandle(handle));
}

static void expect_null_prefix_is_empty_w(const WCHAR *temp_path) {
	WCHAR temp_file[MAX_PATH];

	UINT result = GetTempFileNameW(temp_path, NULL, 0x12345, temp_file);
	TEST_CHECK_EQ(0x2345, result);
	TEST_CHECK(wcscmp(L"2345.TMP", basename_of_w(temp_file)) == 0);
}

static void expect_invalid_parameters_w(const WCHAR *temp_path) {
	WCHAR temp_file[MAX_PATH];

	SetLastError(0);
	TEST_CHECK_EQ(0, GetTempFileNameW(NULL, L"wbo", 0, temp_file));
	TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());

	SetLastError(0);
	TEST_CHECK_EQ(0, GetTempFileNameW(temp_path, L"wbo", 0, NULL));
	TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());
}

int main(void) {
	char temp_path[MAX_PATH];
	DWORD len = GetTempPathA(sizeof(temp_path), temp_path);
	TEST_CHECK(len > 0 && len < sizeof(temp_path));

	expect_fixed_unique_name(temp_path);
	expect_created_file_reopens_like_link(temp_path);
	expect_null_prefix_is_empty(temp_path);

	WCHAR temp_path_w[MAX_PATH];
	int wlen = MultiByteToWideChar(CP_ACP, 0, temp_path, -1, temp_path_w, MAX_PATH);
	TEST_CHECK(wlen > 0);

	expect_fixed_unique_name_w(temp_path_w);
	expect_created_file_reopens_like_link_w(temp_path_w);
	expect_null_prefix_is_empty_w(temp_path_w);
	expect_invalid_parameters_w(temp_path_w);

	return 0;
}
