#include "test_assert.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

static char g_original_dir[MAX_PATH];
static char g_fixture_dir[MAX_PATH];

static uint64_t file_size_from_data(const WIN32_FILE_ATTRIBUTE_DATA *data) {
	return ((uint64_t)data->nFileSizeHigh << 32) | (uint64_t)data->nFileSizeLow;
}

static void create_file_with_content(const char *path, const char *content) {
	HANDLE handle = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	TEST_CHECK_MSG(handle != INVALID_HANDLE_VALUE, "CreateFileA(%s) failed", path);
	DWORD to_write = (DWORD)strlen(content);
	DWORD written = 0;
	TEST_CHECK(WriteFile(handle, content, to_write, &written, NULL));
	TEST_CHECK_EQ(to_write, written);
	TEST_CHECK(CloseHandle(handle));
}

static void setup_fixture(void) {
	DWORD len = GetCurrentDirectoryA(sizeof(g_original_dir), g_original_dir);
	TEST_CHECK(len > 0 && len < sizeof(g_original_dir));

	char temp_path[MAX_PATH];
	DWORD temp_len = GetTempPathA(sizeof(temp_path), temp_path);
	TEST_CHECK(temp_len > 0 && temp_len < sizeof(temp_path));

	char temp_name[MAX_PATH];
	UINT unique = GetTempFileNameA(temp_path, "wbo", 0, temp_name);
	TEST_CHECK(unique != 0);
	TEST_CHECK(DeleteFileA(temp_name));
	TEST_CHECK(CreateDirectoryA(temp_name, NULL));

	strncpy(g_fixture_dir, temp_name, sizeof(g_fixture_dir));
	g_fixture_dir[sizeof(g_fixture_dir) - 1] = '\0';

	TEST_CHECK(SetCurrentDirectoryA(g_fixture_dir));

	create_file_with_content("file.txt", "abc");
	TEST_CHECK(CreateDirectoryA("subdir", NULL));
}

static void cleanup_fixture(void) {
	DeleteFileA("file.txt");
	RemoveDirectoryA("subdir");
	TEST_CHECK(SetCurrentDirectoryA(g_original_dir));
	TEST_CHECK(RemoveDirectoryA(g_fixture_dir));
}

static void test_success_file(void) {
	WIN32_FILE_ATTRIBUTE_DATA data = {0};
	DWORD sentinel = 0xDEADBEEF;

	SetLastError(sentinel);
	TEST_CHECK(GetFileAttributesExA("file.txt", GetFileExInfoStandard, &data));
	TEST_CHECK((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0);
	TEST_CHECK((data.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE) != 0);
	TEST_CHECK_U64_EQ(3, file_size_from_data(&data));
	TEST_CHECK_EQ(sentinel, GetLastError());

	WCHAR file_name[] = L"file.txt";
	SetLastError(sentinel);
	TEST_CHECK(GetFileAttributesExW(file_name, GetFileExInfoStandard, &data));
	TEST_CHECK((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0);
	TEST_CHECK((data.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE) != 0);
	TEST_CHECK_U64_EQ(3, file_size_from_data(&data));
	TEST_CHECK_EQ(sentinel, GetLastError());
}

static void test_success_directory(void) {
	WIN32_FILE_ATTRIBUTE_DATA data = {0};
	WCHAR dir_name[] = L"subdir";

	TEST_CHECK(GetFileAttributesExA("subdir", GetFileExInfoStandard, &data));
	TEST_CHECK((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
	TEST_CHECK_U64_EQ(0, file_size_from_data(&data));

	TEST_CHECK(GetFileAttributesExW(dir_name, GetFileExInfoStandard, &data));
	TEST_CHECK((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
	TEST_CHECK_U64_EQ(0, file_size_from_data(&data));
}

static void test_missing_file(void) {
	WIN32_FILE_ATTRIBUTE_DATA data = {0};
	WCHAR missing_name[] = L"missing.file";

	SetLastError(0xDEADBEEF);
	TEST_CHECK(!GetFileAttributesExA("missing.file", GetFileExInfoStandard, &data));
	TEST_CHECK_EQ(ERROR_FILE_NOT_FOUND, GetLastError());

	SetLastError(0xDEADBEEF);
	TEST_CHECK(!GetFileAttributesExW(missing_name, GetFileExInfoStandard, &data));
	TEST_CHECK_EQ(ERROR_FILE_NOT_FOUND, GetLastError());
}

static void test_null_name(void) {
	WIN32_FILE_ATTRIBUTE_DATA data = {0};

	SetLastError(0xDEADBEEF);
	TEST_CHECK(!GetFileAttributesExA(NULL, GetFileExInfoStandard, &data));
	TEST_CHECK_EQ(ERROR_PATH_NOT_FOUND, GetLastError());

	SetLastError(0xDEADBEEF);
	TEST_CHECK(!GetFileAttributesExW(NULL, GetFileExInfoStandard, &data));
	TEST_CHECK_EQ(ERROR_PATH_NOT_FOUND, GetLastError());
}

static void test_invalid_info_level(void) {
	WIN32_FILE_ATTRIBUTE_DATA data = {0};
	WCHAR file_name[] = L"file.txt";

	SetLastError(0xDEADBEEF);
	TEST_CHECK(!GetFileAttributesExA("file.txt", GetFileExMaxInfoLevel, &data));
	TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());

	SetLastError(0xDEADBEEF);
	TEST_CHECK(!GetFileAttributesExW(file_name, (GET_FILEEX_INFO_LEVELS)123, &data));
	TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());
}

int main(void) {
	setup_fixture();

	test_success_file();
	test_success_directory();
	test_missing_file();
	test_null_name();
	test_invalid_info_level();

	cleanup_fixture();
	return 0;
}
