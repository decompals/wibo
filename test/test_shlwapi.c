#include "test_assert.h"

#include <string.h>
#include <windows.h>
#include <shlwapi.h>

static void test_appends_backslash(void) {
	char path[MAX_PATH] = "C:\\foo";
	char *end = PathAddBackslashA(path);
	TEST_CHECK(end != NULL);
	TEST_CHECK_STR_EQ("C:\\foo\\", path);
	TEST_CHECK(end == path + strlen(path));
}

static void test_existing_backslash(void) {
	char path[MAX_PATH] = "C:\\foo\\";
	char *end = PathAddBackslashA(path);
	TEST_CHECK(end != NULL);
	TEST_CHECK_STR_EQ("C:\\foo\\", path);
	TEST_CHECK(end == path + strlen(path));
}

static void test_empty_string(void) {
	char path[MAX_PATH] = "";
	char *end = PathAddBackslashA(path);
	TEST_CHECK(end != NULL);
	TEST_CHECK_STR_EQ("\\", path);
	TEST_CHECK(end == path + strlen(path));
}

static void test_max_path_limit(void) {
	char path[MAX_PATH];
	memset(path, 'a', sizeof(path));
	path[MAX_PATH - 1] = '\0';

	char *end = PathAddBackslashA(path);
	TEST_CHECK(end == NULL);
	TEST_CHECK(path[MAX_PATH - 2] == 'a');
	TEST_CHECK(path[MAX_PATH - 1] == '\0');
}

int main(void) {
	test_appends_backslash();
	test_existing_backslash();
	test_empty_string();
	test_max_path_limit();
	return 0;
}
