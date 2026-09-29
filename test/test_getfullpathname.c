#include "test_assert.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

static char g_current_directory[MAX_PATH];

static void join_path(char *output, size_t output_size, const char *directory, const char *suffix) {
	int written = snprintf(output, output_size, "%s\\%s", directory, suffix);
	TEST_CHECK(written > 0 && (size_t)written < output_size);
}

static void assert_full_path(const char *input, const char *expected, const char *expected_file_part) {
	char buffer[2 * MAX_PATH];
	char *file_part = (char *)(uintptr_t)1;
	const DWORD sentinel = 0xDEADBEEF;

	SetLastError(sentinel);
	DWORD length = GetFullPathNameA(input, sizeof(buffer), buffer, &file_part);
	TEST_CHECK_EQ(strlen(expected), length);
	TEST_CHECK_STR_EQ(expected, buffer);
	TEST_CHECK_EQ(sentinel, GetLastError());

	if (expected_file_part) {
		TEST_CHECK(file_part != NULL);
		TEST_CHECK_STR_EQ(expected_file_part, file_part);
		TEST_CHECK_EQ(file_part - buffer, strlen(expected) - strlen(expected_file_part));
	} else {
		TEST_CHECK(file_part == NULL);
	}
}

static void test_relative_paths(void) {
	char expected[2 * MAX_PATH];

	join_path(expected, sizeof(expected), g_current_directory, "missing\\component.txt");
	assert_full_path("missing\\component.txt", expected, "component.txt");

	const char *current_part = strrchr(g_current_directory, '\\');
	TEST_CHECK(current_part != NULL && current_part[1] != '\0');
	assert_full_path(".", g_current_directory, current_part + 1);

	char parent[MAX_PATH];
	strcpy(parent, g_current_directory);
	char *last_separator = strrchr(parent, '\\');
	TEST_CHECK(last_separator != NULL && last_separator > parent + 2);
	*last_separator = '\0';
	const char *parent_part = strrchr(parent, '\\');
	TEST_CHECK(parent_part != NULL && parent_part[1] != '\0');
	assert_full_path("..", parent, parent_part + 1);
}

static void test_lexical_normalization(void) {
	char expected[2 * MAX_PATH];

	join_path(expected, sizeof(expected), g_current_directory, "nonexistent\\file.c");
	assert_full_path(".\\nonexistent/alpha\\..\\file.c", expected, "file.c");

	join_path(expected, sizeof(expected), g_current_directory, "missing\\child.txt");
	assert_full_path("missing...\\child.txt...", expected, "child.txt");

	join_path(expected, sizeof(expected), g_current_directory, "nonexistent\\folder\\");
	assert_full_path("nonexistent/folder\\", expected, NULL);

	assert_full_path("Z:\\definitely-missing\\..\\still-missing\\file.", "Z:\\still-missing\\file", "file");
}

static void test_buffer_contract(void) {
	char expected[2 * MAX_PATH];
	join_path(expected, sizeof(expected), g_current_directory, "missing.txt");
	DWORD required = (DWORD)strlen(expected) + 1;
	char *file_part = (char *)(uintptr_t)1;

	SetLastError(0xDEADBEEF);
	TEST_CHECK_EQ(required, GetFullPathNameA("missing.txt", 0, NULL, &file_part));
	TEST_CHECK(file_part == NULL);
	TEST_CHECK_EQ(ERROR_INSUFFICIENT_BUFFER, GetLastError());

	char buffer[2 * MAX_PATH] = "unchanged";
	file_part = (char *)(uintptr_t)1;
	SetLastError(0xDEADBEEF);
	TEST_CHECK_EQ(required, GetFullPathNameA("missing.txt", required - 1, buffer, &file_part));
	TEST_CHECK_STR_EQ("unchanged", buffer);
	TEST_CHECK(file_part == NULL);
	TEST_CHECK_EQ(ERROR_INSUFFICIENT_BUFFER, GetLastError());
}

int main(void) {
	DWORD length = GetCurrentDirectoryA(sizeof(g_current_directory), g_current_directory);
	TEST_CHECK(length > 3 && length < sizeof(g_current_directory));

	test_relative_paths();
	test_lexical_normalization();
	test_buffer_contract();
	return 0;
}
