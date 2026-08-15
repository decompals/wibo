#include <windows.h>

#include "test_assert.h"

static void test_full_copy(void) {
	char buffer[8];
	memset(buffer, 'x', sizeof(buffer));

	LPSTR ret = lstrcpynA(buffer, "abc", sizeof(buffer));

	TEST_CHECK(ret == buffer);
	TEST_CHECK_STR_EQ("abc", buffer);
	TEST_CHECK_EQ('x', buffer[4]);
}

static void test_truncation(void) {
	char buffer[5];
	memset(buffer, 'x', sizeof(buffer));

	LPSTR ret = lstrcpynA(buffer, "abcdef", 4);

	TEST_CHECK(ret == buffer);
	TEST_CHECK_STR_EQ("abc", buffer);
	TEST_CHECK_EQ('x', buffer[4]);
}

static void test_exact_fit(void) {
	char buffer[5];
	memset(buffer, 'x', sizeof(buffer));

	LPSTR ret = lstrcpynA(buffer, "abc", 4);

	TEST_CHECK(ret == buffer);
	TEST_CHECK_STR_EQ("abc", buffer);
	TEST_CHECK_EQ('x', buffer[4]);
}

static void test_one_character_buffer(void) {
	char buffer[2] = {'x', 'y'};

	LPSTR ret = lstrcpynA(buffer, "abc", 1);

	TEST_CHECK(ret == buffer);
	TEST_CHECK_EQ('\0', buffer[0]);
	TEST_CHECK_EQ('y', buffer[1]);
}

static void test_zero_length(void) {
	char buffer[4] = {'a', 'b', 'c', 'd'};

	LPSTR ret = lstrcpynA(buffer, "xyz", 0);

	TEST_CHECK(ret == buffer);
	TEST_CHECK_EQ('a', buffer[0]);
	TEST_CHECK_EQ('b', buffer[1]);
	TEST_CHECK_EQ('c', buffer[2]);
	TEST_CHECK_EQ('d', buffer[3]);
}

static void test_negative_length(void) {
	char buffer[4];
	memset(buffer, 'x', sizeof(buffer));

	LPSTR ret = lstrcpynA(buffer, "ab", -1);

	TEST_CHECK(ret == buffer);
	TEST_CHECK_STR_EQ("ab", buffer);
	TEST_CHECK_EQ('x', buffer[3]);
}

int main(void) {
	test_full_copy();
	test_truncation();
	test_exact_fit();
	test_one_character_buffer();
	test_zero_length();
	test_negative_length();
	return 0;
}
