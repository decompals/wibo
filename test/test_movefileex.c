#include "test_assert.h"
#include <windows.h>

static BOOL move_file(BOOL wide, const char *from, const char *to, DWORD flags) {
	if (!wide)
		return MoveFileExA(from, to, flags);
	WCHAR from_w[MAX_PATH], to_w[MAX_PATH];
	TEST_CHECK(MultiByteToWideChar(CP_ACP, 0, from, -1, from_w, MAX_PATH));
	TEST_CHECK(MultiByteToWideChar(CP_ACP, 0, to, -1, to_w, MAX_PATH));
	return MoveFileExW(from_w, to_w, flags);
}

static void write_file(const char *name, const char *content) {
	HANDLE file = CreateFileA(name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	TEST_CHECK(file != INVALID_HANDLE_VALUE);
	DWORD written;
	TEST_CHECK(WriteFile(file, content, (DWORD)strlen(content), &written, NULL));
	TEST_CHECK_EQ(strlen(content), written);
	TEST_CHECK(CloseHandle(file));
}

static void check_file(const char *name, const char *content) {
	HANDLE file = CreateFileA(name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	TEST_CHECK(file != INVALID_HANDLE_VALUE);
	char buffer[32] = {0};
	DWORD count;
	TEST_CHECK(ReadFile(file, buffer, sizeof(buffer) - 1, &count, NULL));
	TEST_CHECK_EQ(strlen(content), count);
	TEST_CHECK_STR_EQ(content, buffer);
	TEST_CHECK(CloseHandle(file));
}

static void check_missing(const char *name) {
	TEST_CHECK_EQ(INVALID_FILE_ATTRIBUTES, GetFileAttributesA(name));
	TEST_CHECK_EQ(ERROR_FILE_NOT_FOUND, GetLastError());
}

static void test_moves(BOOL wide) {
	write_file("source", "new contents");
	TEST_CHECK(move_file(wide, "source", "dest", MOVEFILE_COPY_ALLOWED));
	check_missing("source");
	check_file("dest", "new contents");
	write_file("source", "replacement");
	TEST_CHECK(!move_file(wide, "source", "dest", 0));
	TEST_CHECK_EQ(ERROR_ALREADY_EXISTS, GetLastError());
	check_file("source", "replacement");
	check_file("dest", "new contents");
	TEST_CHECK(move_file(wide, "source", "dest", MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH));
	check_missing("source");
	check_file("dest", "replacement");
	TEST_CHECK(move_file(wide, "dest", "dest", MOVEFILE_REPLACE_EXISTING));
	check_file("dest", "replacement");
	TEST_CHECK(!move_file(wide, "missing", "dest", MOVEFILE_REPLACE_EXISTING));
	TEST_CHECK_EQ(ERROR_FILE_NOT_FOUND, GetLastError());
	check_file("dest", "replacement");
	TEST_CHECK(!move_file(wide, "dest", "missing/child", 0));
	TEST_CHECK_EQ(ERROR_PATH_NOT_FOUND, GetLastError());
	TEST_CHECK(CreateDirectoryA("dir", NULL));
	TEST_CHECK(!move_file(wide, "dest", "dir", MOVEFILE_REPLACE_EXISTING));
	TEST_CHECK_EQ(ERROR_ACCESS_DENIED, GetLastError());
	TEST_CHECK(CreateDirectoryA("dir2", NULL));
	TEST_CHECK(!move_file(wide, "dir", "dir2", MOVEFILE_REPLACE_EXISTING));
	TEST_CHECK_EQ(ERROR_ACCESS_DENIED, GetLastError());
	TEST_CHECK(RemoveDirectoryA("dir2"));
	TEST_CHECK(move_file(wide, "dir", "dir2", 0));
	TEST_CHECK(RemoveDirectoryA("dir2"));
	check_file("dest", "replacement");
	TEST_CHECK(DeleteFileA("dest"));
}

// Optional destination directory on another volume, for exercising the EXDEV path.
static void test_cross_volume(BOOL wide, const char *directory) {
	char dest[MAX_PATH];
	TEST_CHECK(GetTempFileNameA(directory, "wbo", 0, dest));
	TEST_CHECK(DeleteFileA(dest));
	write_file("source", "cross volume");
	TEST_CHECK(!move_file(wide, "source", dest, 0));
	TEST_CHECK_EQ(ERROR_NOT_SAME_DEVICE, GetLastError());
	check_file("source", "cross volume");
	TEST_CHECK(move_file(wide, "source", dest, MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH));
	check_missing("source");
	check_file(dest, "cross volume");
	write_file("source", "replacement");
	TEST_CHECK(!move_file(wide, "source", dest, MOVEFILE_COPY_ALLOWED));
	TEST_CHECK_EQ(ERROR_ALREADY_EXISTS, GetLastError());
	check_file("source", "replacement");
	check_file(dest, "cross volume");
	TEST_CHECK(
		move_file(wide, "source", dest, MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH));
	check_missing("source");
	check_file(dest, "replacement");
	TEST_CHECK(DeleteFileA(dest));
	TEST_CHECK(CreateDirectoryA("source", NULL));
	TEST_CHECK(!move_file(wide, "source", dest, MOVEFILE_COPY_ALLOWED));
	DWORD error = GetLastError();
	TEST_CHECK(error == ERROR_NOT_SAME_DEVICE || error == ERROR_ACCESS_DENIED);
	TEST_CHECK(RemoveDirectoryA("source"));
}

int main(int argc, char **argv) {
	char original[MAX_PATH], temp[MAX_PATH], fixture[MAX_PATH];
	TEST_CHECK(GetCurrentDirectoryA(MAX_PATH, original));
	TEST_CHECK(GetTempPathA(MAX_PATH, temp));
	TEST_CHECK(GetTempFileNameA(temp, "wbo", 0, fixture));
	TEST_CHECK(DeleteFileA(fixture));
	TEST_CHECK(CreateDirectoryA(fixture, NULL));
	TEST_CHECK(SetCurrentDirectoryA(fixture));
	test_moves(FALSE);
	test_moves(TRUE);
	if (argc > 1) {
		test_cross_volume(FALSE, argv[1]);
		test_cross_volume(TRUE, argv[1]);
	}
	TEST_CHECK(SetCurrentDirectoryA(original));
	TEST_CHECK(RemoveDirectoryA(fixture));
	return 0;
}
