#include "test_assert.h"

#include <wchar.h>
#include <windows.h>

static void check_path(const char *input, const char *expected) {
	char buffer[MAX_PATH];
	char *part = NULL;
	const char *expected_part = strrchr(expected, '\\');
	size_t length = strlen(expected);
	DWORD result = GetFullPathNameA(input, MAX_PATH, buffer, &part);
	TEST_CHECK_EQ(length, result);
	TEST_CHECK_STR_EQ(expected, buffer);
	if (expected_part[1]) {
		TEST_CHECK(part == buffer + (expected_part - expected) + 1);
		TEST_CHECK_STR_EQ(expected_part + 1, part);
	} else {
		TEST_CHECK(part == NULL);
	}
	TEST_CHECK_EQ(length + 1, GetFullPathNameA(input, 0, NULL, NULL));
	TEST_CHECK_EQ(length + 1, GetFullPathNameA(input, length, buffer, NULL));
	TEST_CHECK_EQ(length, GetFullPathNameA(input, length + 1, buffer, NULL));
	TEST_CHECK_STR_EQ(expected, buffer);

	wchar_t wide_input[MAX_PATH];
	wchar_t wide_expected[MAX_PATH];
	wchar_t wide_buffer[MAX_PATH];
	wchar_t *wide_part = NULL;
	TEST_CHECK(MultiByteToWideChar(CP_ACP, 0, input, -1, wide_input, MAX_PATH) > 0);
	TEST_CHECK(MultiByteToWideChar(CP_ACP, 0, expected, -1, wide_expected, MAX_PATH) > 0);
	result = GetFullPathNameW(wide_input, MAX_PATH, wide_buffer, &wide_part);
	TEST_CHECK_EQ(length, result);
	TEST_CHECK(wcscmp(wide_expected, wide_buffer) == 0);
	if (expected_part[1]) {
		TEST_CHECK(wide_part == wide_buffer + (expected_part - expected) + 1);
		TEST_CHECK(wcscmp(wide_expected + (expected_part - expected) + 1, wide_part) == 0);
	} else {
		TEST_CHECK(wide_part == NULL);
	}
	TEST_CHECK_EQ(length + 1, GetFullPathNameW(wide_input, 0, NULL, NULL));
	TEST_CHECK_EQ(length + 1, GetFullPathNameW(wide_input, length, wide_buffer, NULL));
	TEST_CHECK_EQ(length, GetFullPathNameW(wide_input, length + 1, wide_buffer, NULL));
	TEST_CHECK(wcscmp(wide_expected, wide_buffer) == 0);
}

static void check_invalid_name(const char *input) {
	char buffer[MAX_PATH] = "untouched";
	char *part = buffer;
	SetLastError(0xdeadbeef);
	TEST_CHECK_EQ(0, GetFullPathNameA(input, MAX_PATH, buffer, &part));
	TEST_CHECK_EQ(0xdeadbeef, GetLastError());
	TEST_CHECK_STR_EQ("untouched", buffer);
	TEST_CHECK(part == buffer);

	wchar_t wide_input[MAX_PATH];
	wchar_t wide_buffer[MAX_PATH] = L"untouched";
	wchar_t *wide_part = wide_buffer;
	if (input) {
		TEST_CHECK(MultiByteToWideChar(CP_ACP, 0, input, -1, wide_input, MAX_PATH) > 0);
	}
	SetLastError(0xdeadbeef);
	TEST_CHECK_EQ(0, GetFullPathNameW(input ? wide_input : NULL, MAX_PATH, wide_buffer, &wide_part));
	TEST_CHECK_EQ(0xdeadbeef, GetLastError());
	TEST_CHECK(wcscmp(L"untouched", wide_buffer) == 0);
	TEST_CHECK(wide_part == wide_buffer);
}

static void join_path(char *out, const char *base, const char *name) {
	size_t length = strlen(base);
	strcpy(out, base);
	if (length == 0 || out[length - 1] != '\\') {
		strcat(out, "\\");
	}
	strcat(out, name);
}

int main(void) {
	/* No file or directory needs to exist for GetFullPathName. */
	check_path("C:\\wibo-nonexistent\\app\\modules\\module.pdb", "C:\\wibo-nonexistent\\app\\modules\\module.pdb");
	check_path("Z:\\wibo-nonexistent\\app\\modules\\module.pdb", "Z:\\wibo-nonexistent\\app\\modules\\module.pdb");
	check_path("D:\\wibo-nonexistent\\file.pdb", "D:\\wibo-nonexistent\\file.pdb");
	check_path("C:/wibo-nonexistent\\app/./old/../modules/module.pdb",
			   "C:\\wibo-nonexistent\\app\\modules\\module.pdb");
	check_path("C:\\..\\..\\wibo-nonexistent.pdb", "C:\\wibo-nonexistent.pdb");
	check_path("C:\\wibo-nonexistent\\app\\modules\\", "C:\\wibo-nonexistent\\app\\modules\\");
	check_path("C:\\", "C:\\");
	check_path("C:/", "C:\\");

	/* Drive letter and component case are kept as given. */
	check_path("c:\\wibo-nonexistent\\file.pdb", "c:\\wibo-nonexistent\\file.pdb");
	check_path("d:/wibo-nonexistent/file.pdb", "d:\\wibo-nonexistent\\file.pdb");
	check_path("c:\\", "c:\\");
	check_path("C:\\WIBO-Nonexistent\\File.PDB", "C:\\WIBO-Nonexistent\\File.PDB");

	check_path("C:\\wibo-nonexistent\\\\file.pdb", "C:\\wibo-nonexistent\\file.pdb");
	check_path("C:\\wibo-nonexistent\\file.", "C:\\wibo-nonexistent\\file");
	check_path("C:\\wibo-nonexistent\\..", "C:\\");
	check_path("C:\\wibo-nonexistent\\..\\", "C:\\");
	check_path("C:\\wibo-nonexistent\\.", "C:\\wibo-nonexistent");

	/* Resolution is lexical: no host lookup or case correction. */
	check_path("C:\\USR\\BIN\\..\\LIB", "C:\\USR\\LIB");
	check_path("Z:\\USR\\BIN\\..\\LIB\\", "Z:\\USR\\LIB\\");

	/* Intermediate components lose one trailing dot; the final one loses trailing dots and spaces. */
	check_path("C:\\wibo-nonexistent.\\file.pdb", "C:\\wibo-nonexistent\\file.pdb");
	check_path("C:\\wibo-nonexistent\\file. . ", "C:\\wibo-nonexistent\\file");

	/* Final trimming applies after . and .. have been collapsed. */
	check_path("C:\\wibo-nonexistent\\dir..\\.", "C:\\wibo-nonexistent\\dir");
	check_path("C:\\wibo-nonexistent\\dir..\\child\\..", "C:\\wibo-nonexistent\\dir");
	check_path("C:\\wibo-nonexistent\\dir. \\child\\..", "C:\\wibo-nonexistent\\dir");
	check_path("C:\\...\\.", "C:\\");
	check_path("C:\\wibo-nonexistent\\dir..\\child\\..\\", "C:\\wibo-nonexistent\\dir.\\");
	check_path("C:\\wibo-nonexistent\\dir. \\child\\..\\", "C:\\wibo-nonexistent\\dir. \\");
	check_path("\\\\server\\share\\dir..\\child\\..", "\\\\server\\share\\dir");
	check_path("\\\\?\\C:\\dir..\\child\\..", "\\\\?\\C:\\dir");

	check_path("\\\\server\\share\\dir\\..\\file.pdb", "\\\\server\\share\\file.pdb");

	/* A server name alone has no file part. */
	char server[MAX_PATH];
	char *server_part = server;
	TEST_CHECK_EQ(8, GetFullPathNameA("\\\\server", MAX_PATH, server, &server_part));
	TEST_CHECK_STR_EQ("\\\\server", server);
	TEST_CHECK(server_part == NULL);

	/* Pre-Win7 leaves the last error and outputs untouched. */
	check_invalid_name(NULL);
	check_invalid_name("");

	/* Names of only spaces fail after lpFilePart has been reset (Wine behaviour). */
	SetLastError(0xdeadbeef);
	TEST_CHECK_EQ(0, GetFullPathNameA("   ", MAX_PATH, server, &server_part));
	TEST_CHECK_EQ(0xdeadbeef, GetLastError());
	TEST_CHECK(server_part == NULL);

	/* GetFullPathName still normalizes paths with the extended prefix. */
	check_path("\\\\?\\Z:\\foo\\..\\bar", "\\\\?\\Z:\\bar");
	check_path("\\\\?\\C:/wibo-nonexistent/./file.pdb", "\\\\?\\C:\\wibo-nonexistent\\file.pdb");
	check_path("\\\\?\\C:\\wibo-nonexistent\\file. . ", "\\\\?\\C:\\wibo-nonexistent\\file");
	check_path("\\\\?\\UNC\\server\\share\\dir\\..\\file.pdb", "\\\\?\\UNC\\server\\share\\file.pdb");
	check_path("\\\\?\\foo\\..", "\\\\?\\");

	char cwd[MAX_PATH];
	char expected[MAX_PATH];
	DWORD length = GetCurrentDirectoryA(MAX_PATH, cwd);
	TEST_CHECK(length > 0 && length + sizeof("\\wibo-nonexistent.pdb") <= MAX_PATH);

	join_path(expected, cwd, "wibo-nonexistent.pdb");
	check_path("wibo-nonexistent.pdb", expected);
	check_path(".\\wibo-nonexistent.pdb", expected);

	/* A leading separator is the root of the current drive. */
	char root[4] = {cwd[0], ':', '\\', '\0'};
	join_path(expected, root, "wibo-nonexistent\\file.pdb");
	check_path("\\wibo-nonexistent\\file.pdb", expected);
	check_path("/wibo-nonexistent/file.pdb", expected);

	/* Drive-relative paths on another drive resolve against that drive's root. */
	char other_drive = (cwd[0] == 'D' || cwd[0] == 'd') ? 'E' : 'D';
	char drive_relative[] = {other_drive, ':', 'w', 'i', 'b', 'o', '.', 'p', 'd', 'b', '\0'};
	char drive_expected[] = {other_drive, ':', '\\', 'w', 'i', 'b', 'o', '.', 'p', 'd', 'b', '\0'};
	check_path(drive_relative, drive_expected);

	/* Drive-relative paths on the current drive resolve against the cwd. */
	char same_drive[MAX_PATH] = {cwd[0], ':', '\0'};
	strcat(same_drive, "wibo-nonexistent.pdb");
	join_path(expected, cwd, "wibo-nonexistent.pdb");
	check_path(same_drive, expected);

	char parent[MAX_PATH];
	strcpy(parent, cwd);
	char *last = strrchr(parent, '\\');
	TEST_CHECK(last != NULL);
	last[last - parent == 2 ? 1 : 0] = '\0';
	join_path(expected, parent, "wibo-nonexistent.pdb");
	check_path("..\\wibo-nonexistent.pdb", expected);
	return 0;
}
