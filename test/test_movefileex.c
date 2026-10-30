#include "test_assert.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

static char g_original_dir[MAX_PATH];
static char g_fixture_dir[MAX_PATH];

static void write_file(const char *path, const char *content) {
	HANDLE handle = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	TEST_CHECK_MSG(handle != INVALID_HANDLE_VALUE, "CreateFileA(%s) failed", path);
	DWORD to_write = (DWORD)strlen(content);
	DWORD written = 0;
	TEST_CHECK(WriteFile(handle, content, to_write, &written, NULL));
	TEST_CHECK_EQ(to_write, written);
	TEST_CHECK(CloseHandle(handle));
}

static void check_file(const char *path, const char *expected) {
	HANDLE handle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
								OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	TEST_CHECK_MSG(handle != INVALID_HANDLE_VALUE, "CreateFileA(%s) failed", path);
	char buffer[64] = {0};
	DWORD read = 0;
	TEST_CHECK(ReadFile(handle, buffer, sizeof(buffer) - 1, &read, NULL));
	TEST_CHECK(CloseHandle(handle));
	TEST_CHECK_STR_EQ(expected, buffer);
}

static void check_missing(const char *path) {
	TEST_CHECK_MSG(GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES, "%s still exists", path);
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
}

static void cleanup_fixture(void) {
	TEST_CHECK(SetCurrentDirectoryA(g_original_dir));
	TEST_CHECK(RemoveDirectoryA(g_fixture_dir));
}

static void test_plain_rename(void) {
	write_file("src.txt", "plain");
	TEST_CHECK(MoveFileExA("src.txt", "dst.txt", 0));
	check_missing("src.txt");
	check_file("dst.txt", "plain");
	TEST_CHECK(DeleteFileA("dst.txt"));
}

static void test_existing_without_replace(void) {
	write_file("src.txt", "new");
	write_file("dst.txt", "old");
	SetLastError(0xDEADBEEF);
	TEST_CHECK(!MoveFileExA("src.txt", "dst.txt", 0));
	TEST_CHECK_EQ(ERROR_ALREADY_EXISTS, GetLastError());
	check_file("src.txt", "new");
	check_file("dst.txt", "old");

	SetLastError(0xDEADBEEF);
	TEST_CHECK(!MoveFileExA("src.txt", "dst.txt", MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH));
	TEST_CHECK_EQ(ERROR_ALREADY_EXISTS, GetLastError());
	check_file("src.txt", "new");
	check_file("dst.txt", "old");

	TEST_CHECK(DeleteFileA("src.txt"));
	TEST_CHECK(DeleteFileA("dst.txt"));
}

static void test_existing_with_replace(void) {
	write_file("src.txt", "new");
	write_file("dst.txt", "old contents");
	TEST_CHECK(MoveFileExA("src.txt", "dst.txt", MOVEFILE_REPLACE_EXISTING));
	check_missing("src.txt");
	check_file("dst.txt", "new");

	write_file("src.txt", "newer");
	TEST_CHECK(
		MoveFileExA("src.txt", "dst.txt", MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH));
	check_missing("src.txt");
	check_file("dst.txt", "newer");
	TEST_CHECK(DeleteFileA("dst.txt"));
}

static void test_replace_directory_fails(void) {
	write_file("src.txt", "data");
	TEST_CHECK(CreateDirectoryA("dir", NULL));
	SetLastError(0xDEADBEEF);
	TEST_CHECK(!MoveFileExA("src.txt", "dir", MOVEFILE_REPLACE_EXISTING));
	TEST_CHECK_EQ(ERROR_ACCESS_DENIED, GetLastError());
	check_file("src.txt", "data");
	TEST_CHECK(DeleteFileA("src.txt"));

	TEST_CHECK(CreateDirectoryA("srcdir", NULL));
	write_file("srcdir\\inner.txt", "inner");
	const DWORD flags[] = {MOVEFILE_REPLACE_EXISTING, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED};
	for (unsigned i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i) {
		SetLastError(0xDEADBEEF);
		TEST_CHECK(!MoveFileExA("srcdir", "dir", flags[i]));
		TEST_CHECK_EQ(ERROR_ACCESS_DENIED, GetLastError());
		check_file("srcdir\\inner.txt", "inner");
		TEST_CHECK((GetFileAttributesA("dir") & FILE_ATTRIBUTE_DIRECTORY) != 0);
	}
	TEST_CHECK(DeleteFileA("srcdir\\inner.txt"));
	TEST_CHECK(RemoveDirectoryA("srcdir"));
	TEST_CHECK(RemoveDirectoryA("dir"));
}

static void test_move_directory(void) {
	TEST_CHECK(CreateDirectoryA("dir1", NULL));
	write_file("dir1\\inner.txt", "inner");
	TEST_CHECK(MoveFileExA("dir1", "dir2", 0));
	check_missing("dir1");
	check_file("dir2\\inner.txt", "inner");
	TEST_CHECK(DeleteFileA("dir2\\inner.txt"));
	TEST_CHECK(RemoveDirectoryA("dir2"));
}

static void test_missing_source(void) {
	SetLastError(0xDEADBEEF);
	TEST_CHECK(!MoveFileExA("missing.txt", "dst.txt", MOVEFILE_REPLACE_EXISTING));
	TEST_CHECK_EQ(ERROR_FILE_NOT_FOUND, GetLastError());
	check_missing("dst.txt");

	SetLastError(0xDEADBEEF);
	TEST_CHECK(!MoveFileExA("nodir\\missing.txt", "dst.txt", 0));
	TEST_CHECK_EQ(ERROR_PATH_NOT_FOUND, GetLastError());
}

static void test_wide(void) {
	write_file("wsrc.txt", "wide");
	TEST_CHECK(MoveFileExW(L"wsrc.txt", L"wdst.txt", 0));
	check_missing("wsrc.txt");
	check_file("wdst.txt", "wide");

	write_file("wsrc.txt", "wide2");
	SetLastError(0xDEADBEEF);
	TEST_CHECK(!MoveFileExW(L"wsrc.txt", L"wdst.txt", 0));
	TEST_CHECK_EQ(ERROR_ALREADY_EXISTS, GetLastError());
	check_file("wdst.txt", "wide");

	TEST_CHECK(MoveFileExW(L"wsrc.txt", L"wdst.txt", MOVEFILE_REPLACE_EXISTING));
	check_missing("wsrc.txt");
	check_file("wdst.txt", "wide2");
	TEST_CHECK(DeleteFileA("wdst.txt"));
}

static void test_movefile_existing(void) {
	write_file("src.txt", "new");
	write_file("dst.txt", "old");
	SetLastError(0xDEADBEEF);
	TEST_CHECK(!MoveFileA("src.txt", "dst.txt"));
	TEST_CHECK_EQ(ERROR_ALREADY_EXISTS, GetLastError());
	TEST_CHECK(DeleteFileA("dst.txt"));
	TEST_CHECK(MoveFileA("src.txt", "dst.txt"));
	check_missing("src.txt");
	check_file("dst.txt", "new");
	TEST_CHECK(DeleteFileA("dst.txt"));
}

static void test_delay_until_reboot(void) {
	SetLastError(0xDEADBEEF);
	TEST_CHECK(MoveFileExA("missing.txt", "dst.txt", MOVEFILE_DELAY_UNTIL_REBOOT));
	TEST_CHECK_EQ(0xDEADBEEF, GetLastError());
	check_missing("dst.txt");

	write_file("src.txt", "new");
	write_file("dst.txt", "old");
	TEST_CHECK(MoveFileExA("src.txt", "dst.txt", MOVEFILE_DELAY_UNTIL_REBOOT));
	TEST_CHECK(MoveFileExA("src.txt", "dst.txt", MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_COPY_ALLOWED));
	TEST_CHECK(MoveFileExA("src.txt", NULL, MOVEFILE_DELAY_UNTIL_REBOOT));
	TEST_CHECK(MoveFileExW(L"src.txt", NULL, MOVEFILE_DELAY_UNTIL_REBOOT));
	check_file("src.txt", "new");
	check_file("dst.txt", "old");
	TEST_CHECK(DeleteFileA("src.txt"));
	TEST_CHECK(DeleteFileA("dst.txt"));
}

static void test_null_destination_deletes(void) {
	write_file("src.txt", "data");
	TEST_CHECK(MoveFileExA("src.txt", NULL, 0));
	check_missing("src.txt");

	write_file("src.txt", "data");
	TEST_CHECK(MoveFileExW(L"src.txt", NULL, MOVEFILE_REPLACE_EXISTING));
	check_missing("src.txt");

	SetLastError(0xDEADBEEF);
	TEST_CHECK(!MoveFileExA("missing.txt", NULL, 0));
	TEST_CHECK_EQ(ERROR_FILE_NOT_FOUND, GetLastError());

	TEST_CHECK(CreateDirectoryA("dir", NULL));
	SetLastError(0xDEADBEEF);
	TEST_CHECK(!MoveFileExA("dir", NULL, 0));
	TEST_CHECK_EQ(ERROR_ACCESS_DENIED, GetLastError());
	TEST_CHECK(RemoveDirectoryA("dir"));
}

static void test_missing_destination_directory(void) {
	write_file("src.txt", "data");
	TEST_CHECK(CreateDirectoryA("dir", NULL));
	const DWORD flags[] = {0, MOVEFILE_REPLACE_EXISTING, MOVEFILE_COPY_ALLOWED};
	for (unsigned i = 0; i < sizeof(flags) / sizeof(flags[0]); ++i) {
		SetLastError(0xDEADBEEF);
		TEST_CHECK(!MoveFileExA("src.txt", "nodir\\dst.txt", flags[i]));
		TEST_CHECK_EQ(ERROR_PATH_NOT_FOUND, GetLastError());
	}
	SetLastError(0xDEADBEEF);
	TEST_CHECK(!MoveFileExA("src.txt", "no1\\no2\\dst.txt", 0));
	TEST_CHECK_EQ(ERROR_PATH_NOT_FOUND, GetLastError());
	SetLastError(0xDEADBEEF);
	TEST_CHECK(!MoveFileExA("dir", "nodir\\dir", 0));
	TEST_CHECK_EQ(ERROR_PATH_NOT_FOUND, GetLastError());
	SetLastError(0xDEADBEEF);
	TEST_CHECK(!MoveFileA("src.txt", "nodir\\dst.txt"));
	TEST_CHECK_EQ(ERROR_PATH_NOT_FOUND, GetLastError());
	check_file("src.txt", "data");
	TEST_CHECK(RemoveDirectoryA("dir"));
	TEST_CHECK(DeleteFileA("src.txt"));
}

static void write_file_with_times(const char *path, const char *content, const FILETIME *access_time,
								  const FILETIME *write_time) {
	write_file(path, content);
	HANDLE handle = CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	TEST_CHECK(handle != INVALID_HANDLE_VALUE);
	TEST_CHECK(SetFileTime(handle, NULL, access_time, write_time));
	TEST_CHECK(CloseHandle(handle));
}

static void check_times(const char *path, const FILETIME *access_time, const FILETIME *write_time) {
	WIN32_FILE_ATTRIBUTE_DATA attributes;
	TEST_CHECK(GetFileAttributesExA(path, GetFileExInfoStandard, &attributes));
	TEST_CHECK_EQ(write_time->dwLowDateTime, attributes.ftLastWriteTime.dwLowDateTime);
	TEST_CHECK_EQ(write_time->dwHighDateTime, attributes.ftLastWriteTime.dwHighDateTime);
	TEST_CHECK_EQ(access_time->dwLowDateTime, attributes.ftLastAccessTime.dwLowDateTime);
	TEST_CHECK_EQ(access_time->dwHighDateTime, attributes.ftLastAccessTime.dwHighDateTime);
}

static void test_case_only_rename(void) {
	write_file("case.txt", "data");
	TEST_CHECK(MoveFileExA("case.txt", "CASE.TXT", 0));
	check_file("case.txt", "data");
	TEST_CHECK(DeleteFileA("case.txt"));
}

static void test_cross_volume_dirs(const char *source_dir, const char *destination_dir) {
	const FILETIME access_time = {0x11111100, 0x01b00000};
	const FILETIME write_time = {0x12345600, 0x01c00000};
	char source[MAX_PATH * 2];
	char destination[MAX_PATH * 2];

	snprintf(source, sizeof(source), "%s\\file.txt", source_dir);
	snprintf(destination, sizeof(destination), "%s\\file.txt", destination_dir);
	write_file_with_times(source, "moved", &access_time, &write_time);
	TEST_CHECK(MoveFileExA(source, destination, MOVEFILE_COPY_ALLOWED));
	check_missing(source);
	check_times(destination, &access_time, &write_time);
	check_file(destination, "moved");

	write_file_with_times(source, "replaced", &access_time, &write_time);
	TEST_CHECK(MoveFileA(source, destination) == FALSE);
	TEST_CHECK(MoveFileExA(source, destination, MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING));
	check_missing(source);
	check_times(destination, &access_time, &write_time);
	check_file(destination, "replaced");
	TEST_CHECK(DeleteFileA(destination));

	snprintf(source, sizeof(source), "%s\\dir", source_dir);
	snprintf(destination, sizeof(destination), "%s\\dir", destination_dir);
	TEST_CHECK(CreateDirectoryA(source, NULL));
	SetLastError(0xDEADBEEF);
	TEST_CHECK(!MoveFileExA(source, destination, 0));
	TEST_CHECK_EQ(ERROR_NOT_SAME_DEVICE, GetLastError());
	SetLastError(0xDEADBEEF);
	TEST_CHECK(!MoveFileExA(source, destination, MOVEFILE_COPY_ALLOWED));
	TEST_CHECK_EQ(ERROR_ACCESS_DENIED, GetLastError());
	SetLastError(0xDEADBEEF);
	TEST_CHECK(!MoveFileA(source, destination));
	TEST_CHECK_EQ(ERROR_ACCESS_DENIED, GetLastError());
	check_missing(destination);
	TEST_CHECK(RemoveDirectoryA(source));
}

static void test_cross_volume(void) {
	char other_dir[MAX_PATH];
	snprintf(other_dir, sizeof(other_dir), "Z:\\dev\\shm\\wibo-movefileex-%lu", GetCurrentProcessId());
	if (!CreateDirectoryA(other_dir, NULL)) {
		printf("movefileex: skipping cross-volume test (no %s)\n", other_dir);
		return;
	}
	char probe_source[MAX_PATH * 2];
	char probe_destination[MAX_PATH * 2];
	snprintf(probe_source, sizeof(probe_source), "%s\\probe.txt", g_fixture_dir);
	snprintf(probe_destination, sizeof(probe_destination), "%s\\probe.txt", other_dir);
	write_file(probe_source, "probe");
	SetLastError(0xDEADBEEF);
	if (MoveFileExA(probe_source, probe_destination, 0)) {
		printf("movefileex: skipping cross-volume test (same filesystem)\n");
		TEST_CHECK(DeleteFileA(probe_destination));
	} else {
		TEST_CHECK_EQ(ERROR_NOT_SAME_DEVICE, GetLastError());
		TEST_CHECK(DeleteFileA(probe_source));
		test_cross_volume_dirs(g_fixture_dir, other_dir);
	}
	TEST_CHECK(RemoveDirectoryA(other_dir));
}

int main(void) {
	setup_fixture();
	test_plain_rename();
	test_existing_without_replace();
	test_existing_with_replace();
	test_replace_directory_fails();
	test_move_directory();
	test_case_only_rename();
	test_missing_source();
	test_wide();
	test_movefile_existing();
	test_delay_until_reboot();
	test_null_destination_deletes();
	test_missing_destination_directory();
	test_cross_volume();
	cleanup_fixture();
	printf("movefileex: passed\n");
	return 0;
}
