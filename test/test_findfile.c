#include "test_assert.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static char g_original_dir[MAX_PATH];
static char g_fixture_dir[MAX_PATH];

static const char *leaf_name(const char *path) {
	const char *back = strrchr(path, '\\');
	const char *forward = strrchr(path, '/');
	const char *candidate = back;
	if (!candidate || (forward && forward > candidate)) {
		candidate = forward;
	}
	if (candidate && candidate[1] != '\0') {
		return candidate + 1;
	}
	return path;
}

static void join_path(char *buffer, size_t buffer_size, const char *a, const char *b) {
	int written = snprintf(buffer, buffer_size, "%s\\%s", a, b);
	TEST_CHECK_MSG(written > 0 && (size_t)written < buffer_size, "join_path overflow");
}

static void create_file_with_content(const char *path, const char *content) {
	HANDLE handle = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	TEST_CHECK_MSG(handle != INVALID_HANDLE_VALUE, "CreateFileA(%s) failed", path);
	DWORD to_write = (DWORD)strlen(content);
	DWORD written = 0;
	BOOL ok = WriteFile(handle, content, to_write, &written, NULL);
	TEST_CHECK(ok);
	TEST_CHECK_EQ(to_write, written);
	TEST_CHECK(CloseHandle(handle));
}

static void setup_fixture(void) {
	DWORD len = GetCurrentDirectoryA(sizeof(g_original_dir), g_original_dir);
	TEST_CHECK(len > 0 && len < sizeof(g_original_dir));

	char temp_path[MAX_PATH];
	DWORD tmp_len = GetTempPathA(sizeof(temp_path), temp_path);
	TEST_CHECK(tmp_len > 0 && tmp_len < sizeof(temp_path));

	char temp_name[MAX_PATH];
	UINT unique = GetTempFileNameA(temp_path, "wbo", 0, temp_name);
	TEST_CHECK(unique != 0);
	TEST_CHECK(DeleteFileA(temp_name));
	TEST_CHECK(CreateDirectoryA(temp_name, NULL));
	strncpy(g_fixture_dir, temp_name, sizeof(g_fixture_dir));
	g_fixture_dir[sizeof(g_fixture_dir) - 1] = '\0';

	TEST_CHECK(SetCurrentDirectoryA(g_fixture_dir));

	TEST_CHECK(CreateDirectoryA("dir", NULL));
	TEST_CHECK(CreateDirectoryA("dir\\child", NULL));
	TEST_CHECK(CreateDirectoryA("dir_extra", NULL));

	create_file_with_content("dir\\file.txt", "file.txt\n");
	create_file_with_content("dir\\file.bin", "file.bin\n");
	create_file_with_content("dir\\data01.txt", "data01\n");
	create_file_with_content("dir\\data02.txt", "data02\n");
	create_file_with_content("dir\\data10.txt", "data10\n");
	create_file_with_content("dir\\child\\nested.txt", "nested\n");
	create_file_with_content("dir_extra\\other.txt", "other\n");
}

static void cleanup_fixture(void) {
	TEST_CHECK(SetCurrentDirectoryA(g_original_dir));

	char path[MAX_PATH];

	join_path(path, sizeof(path), g_fixture_dir, "dir\\child\\nested.txt");
	DeleteFileA(path);
	join_path(path, sizeof(path), g_fixture_dir, "dir\\child");
	RemoveDirectoryA(path);

	join_path(path, sizeof(path), g_fixture_dir, "dir\\file.txt");
	DeleteFileA(path);
	join_path(path, sizeof(path), g_fixture_dir, "dir\\file.bin");
	DeleteFileA(path);
	join_path(path, sizeof(path), g_fixture_dir, "dir\\data01.txt");
	DeleteFileA(path);
	join_path(path, sizeof(path), g_fixture_dir, "dir\\data02.txt");
	DeleteFileA(path);
	join_path(path, sizeof(path), g_fixture_dir, "dir\\data10.txt");
	DeleteFileA(path);
	join_path(path, sizeof(path), g_fixture_dir, "dir");
	RemoveDirectoryA(path);

	join_path(path, sizeof(path), g_fixture_dir, "dir_extra\\other.txt");
	DeleteFileA(path);
	join_path(path, sizeof(path), g_fixture_dir, "dir_extra");
	RemoveDirectoryA(path);

	RemoveDirectoryA(g_fixture_dir);
}

static HANDLE find_first_checked(const char *pattern, WIN32_FIND_DATAA *out_data) {
	SetLastError(0xDEADBEEF);
	HANDLE handle = FindFirstFileA(pattern, out_data);
	TEST_CHECK_MSG(handle != INVALID_HANDLE_VALUE, "FindFirstFileA failed for %s (err=%lu)", pattern, GetLastError());
	return handle;
}

static void test_empty_pattern(void) {
	WIN32_FIND_DATAA data;
	SetLastError(0xDEADBEEF);
	HANDLE handle = FindFirstFileA("", &data);
	TEST_CHECK(handle == INVALID_HANDLE_VALUE);
	TEST_CHECK_EQ(ERROR_PATH_NOT_FOUND, GetLastError());
}

static void test_null_pattern(void) {
	WIN32_FIND_DATAA data;
	SetLastError(0xDEADBEEF);
	HANDLE handle = FindFirstFileA(NULL, &data);
	TEST_CHECK(handle == INVALID_HANDLE_VALUE);
	TEST_CHECK_EQ(ERROR_PATH_NOT_FOUND, GetLastError());
}

static void test_dot_pattern(void) {
	WIN32_FIND_DATAA data;
	HANDLE handle = find_first_checked(".", &data);
	TEST_CHECK(handle != INVALID_HANDLE_VALUE);
	TEST_CHECK(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
	TEST_CHECK_STR_EQ(leaf_name(g_fixture_dir), data.cFileName);

	SetLastError(0xDEADBEEF);
	TEST_CHECK(!FindNextFileA(handle, &data));
	TEST_CHECK_EQ(ERROR_NO_MORE_FILES, GetLastError());
	TEST_CHECK(FindClose(handle));
}

static void test_trailing_slash(void) {
	WIN32_FIND_DATAA data;
	SetLastError(0xDEADBEEF);
	HANDLE handle = FindFirstFileA("dir\\", &data);
	TEST_CHECK(handle == INVALID_HANDLE_VALUE);
	TEST_CHECK_EQ(ERROR_FILE_NOT_FOUND, GetLastError());

	SetLastError(0xDEADBEEF);
	handle = FindFirstFileA("dir/", &data);
	TEST_CHECK(handle == INVALID_HANDLE_VALUE);
	TEST_CHECK_EQ(ERROR_FILE_NOT_FOUND, GetLastError());
}

static void test_trailing_dot(void) {
	WIN32_FIND_DATAA data;
	HANDLE handle = find_first_checked("dir\\.", &data);
	TEST_CHECK(handle != INVALID_HANDLE_VALUE);
	TEST_CHECK(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
	TEST_CHECK_STR_EQ("dir", data.cFileName);
	TEST_CHECK(FindClose(handle));

	handle = find_first_checked("dir/.", &data);
	TEST_CHECK(handle != INVALID_HANDLE_VALUE);
	TEST_CHECK(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
	TEST_CHECK_STR_EQ("dir", data.cFileName);
	TEST_CHECK(FindClose(handle));
}

static void test_direct_file_paths(void) {
	WIN32_FIND_DATAA data;
	HANDLE handle = find_first_checked("dir\\file.txt", &data);
	TEST_CHECK(handle != INVALID_HANDLE_VALUE);
	TEST_CHECK((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0);
	TEST_CHECK_STR_EQ("file.txt", data.cFileName);
	SetLastError(0xDEADBEEF);
	TEST_CHECK(!FindNextFileA(handle, &data));
	TEST_CHECK_EQ(ERROR_NO_MORE_FILES, GetLastError());
	TEST_CHECK(FindClose(handle));

	handle = find_first_checked("dir/file.txt", &data);
	TEST_CHECK(handle != INVALID_HANDLE_VALUE);
	TEST_CHECK((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0);
	TEST_CHECK_STR_EQ("file.txt", data.cFileName);
	SetLastError(0xDEADBEEF);
	TEST_CHECK(!FindNextFileA(handle, &data));
	TEST_CHECK_EQ(ERROR_NO_MORE_FILES, GetLastError());
	TEST_CHECK(FindClose(handle));
}

static int compare_strings(const void *a, const void *b) {
	const char *sa = (const char *)a;
	const char *sb = (const char *)b;
	return strcmp(sa, sb);
}

static void collect_matches(const char *pattern, char matches[][MAX_PATH], size_t *out_count) {
	*out_count = 0;
	WIN32_FIND_DATAA data;
	SetLastError(0xDEADBEEF);
	HANDLE handle = FindFirstFileA(pattern, &data);
	if (handle == INVALID_HANDLE_VALUE) {
		*out_count = 0;
		return;
	}
	do {
		strncpy(matches[*out_count], data.cFileName, MAX_PATH);
		matches[*out_count][MAX_PATH - 1] = '\0';
		(*out_count)++;
		TEST_CHECK(*out_count < 64);
	} while (FindNextFileA(handle, &data));
	TEST_CHECK_EQ(ERROR_NO_MORE_FILES, GetLastError());
	TEST_CHECK(FindClose(handle));
}

static void test_wildcard_star(void) {
	char matches[64][MAX_PATH];
	size_t count = 0;
	collect_matches("dir\\*.txt", matches, &count);
	TEST_CHECK(count >= 3);
	qsort(matches, count, sizeof(matches[0]), compare_strings);

	bool saw_data01 = false;
	bool saw_data02 = false;
	bool saw_file = false;

	for (size_t i = 0; i < count; ++i) {
		saw_data01 = saw_data01 || strcmp(matches[i], "data01.txt") == 0;
		saw_data02 = saw_data02 || strcmp(matches[i], "data02.txt") == 0;
		saw_file = saw_file || strcmp(matches[i], "file.txt") == 0;
	}

	TEST_CHECK(saw_data01);
	TEST_CHECK(saw_data02);
	TEST_CHECK(saw_file);
}

static void test_wildcard_question(void) {
	char matches[64][MAX_PATH];
	size_t count = 0;
	collect_matches("dir\\data0?.txt", matches, &count);
	TEST_CHECK_EQ(2, count);
	qsort(matches, count, sizeof(matches[0]), compare_strings);
	TEST_CHECK_STR_EQ("data01.txt", matches[0]);
	TEST_CHECK_STR_EQ("data02.txt", matches[1]);

	count = 0;
	collect_matches("dir\\.\\data1?.txt", matches, &count);
	TEST_CHECK_EQ(1, count);
	TEST_CHECK_STR_EQ("data10.txt", matches[0]);

	count = 0;
	collect_matches("dir\\child\\..\\data??.txt", matches, &count);
	TEST_CHECK_EQ(3, count);
	qsort(matches, count, sizeof(matches[0]), compare_strings);
	TEST_CHECK_STR_EQ("data01.txt", matches[0]);
	TEST_CHECK_STR_EQ("data02.txt", matches[1]);
	TEST_CHECK_STR_EQ("data10.txt", matches[2]);
}

static void test_wildcard_in_directory_segment(void) {
	WIN32_FIND_DATAA data;
	SetLastError(0xDEADBEEF);
	HANDLE handle = FindFirstFileA("dir*\\file.txt", &data);
	TEST_CHECK(handle == INVALID_HANDLE_VALUE);
	TEST_CHECK_EQ(ERROR_INVALID_NAME, GetLastError());

	SetLastError(0xDEADBEEF);
	handle = FindFirstFileA("dir*\\child\\nested.txt", &data);
	TEST_CHECK(handle == INVALID_HANDLE_VALUE);
	TEST_CHECK_EQ(ERROR_INVALID_NAME, GetLastError());
}

static void test_directory_iteration_includes_special_entries(void) {
	char matches[64][MAX_PATH];
	size_t count = 0;
	collect_matches("dir\\*", matches, &count);
	TEST_CHECK(count >= 5);

	bool saw_dot = false;
	bool saw_dotdot = false;
	bool saw_child = false;

	for (size_t i = 0; i < count; ++i) {
		saw_dot = saw_dot || strcmp(matches[i], ".") == 0;
		saw_dotdot = saw_dotdot || strcmp(matches[i], "..") == 0;
		saw_child = saw_child || strcmp(matches[i], "child") == 0;
	}

	TEST_CHECK(saw_dot);
	TEST_CHECK(saw_dotdot);
	TEST_CHECK(saw_child);
}

static void test_findclose_invalid_handle(void) {
	SetLastError(0xDEADBEEF);
	TEST_CHECK(!FindClose(NULL));
	TEST_CHECK_EQ(ERROR_INVALID_HANDLE, GetLastError());
}

int main(void) {
	setup_fixture();

	test_empty_pattern();
	test_null_pattern();
	test_dot_pattern();
	test_trailing_slash();
	test_trailing_dot();
	test_direct_file_paths();
	test_wildcard_star();
	test_wildcard_question();
	test_wildcard_in_directory_segment();
	test_directory_iteration_includes_special_entries();
	test_findclose_invalid_handle();

	cleanup_fixture();
	return EXIT_SUCCESS;
}
