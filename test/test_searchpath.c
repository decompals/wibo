#include <windows.h>

#include <stdio.h>

#include "test_assert.h"

static const char kFileName[] = "test_searchpath.tmp";

static void create_file(void) {
	HANDLE file = CreateFileA(kFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
	TEST_CHECK_MSG(file != INVALID_HANDLE_VALUE, "CreateFileA failed: %lu", GetLastError());
	TEST_CHECK(CloseHandle(file));
}

static void test_finds_file_in_current_directory(void) {
	char buffer[MAX_PATH];
	char *file_part = NULL;
	memset(buffer, 0, sizeof(buffer));
	DWORD length = SearchPathA(".", kFileName, NULL, MAX_PATH, buffer, &file_part);
	TEST_CHECK_MSG(length != 0, "SearchPathA failed: %lu", GetLastError());
	TEST_CHECK_EQ(strlen(buffer), length);
	TEST_CHECK_MSG(file_part != NULL, "SearchPathA did not report the file part");
	TEST_CHECK(strcmp(file_part, kFileName) == 0);
	TEST_CHECK(GetFileAttributesA(buffer) != INVALID_FILE_ATTRIBUTES);
}

static void test_appends_extension(void) {
	char buffer[MAX_PATH];
	DWORD length = SearchPathA(".", "test_searchpath", ".tmp", MAX_PATH, buffer, NULL);
	TEST_CHECK_MSG(length != 0, "SearchPathA(extension) failed: %lu", GetLastError());
	TEST_CHECK(GetFileAttributesA(buffer) != INVALID_FILE_ATTRIBUTES);
}

static void test_reports_required_size(void) {
	char buffer[4];
	DWORD length = SearchPathA(".", kFileName, NULL, sizeof(buffer), buffer, NULL);
	TEST_CHECK_MSG(length > sizeof(buffer), "expected the required size, got %lu", length);
}

static void test_missing_file(void) {
	char buffer[MAX_PATH];
	SetLastError(0xdeadbeef);
	DWORD length = SearchPathA(".", "test_searchpath_no_such_file", NULL, MAX_PATH, buffer, NULL);
	TEST_CHECK_EQ(0u, length);
	TEST_CHECK_EQ(ERROR_FILE_NOT_FOUND, GetLastError());
}

int main(void) {
	create_file();
	test_finds_file_in_current_directory();
	test_appends_extension();
	test_reports_required_size();
	test_missing_file();
	DeleteFileA(kFileName);
	return 0;
}
