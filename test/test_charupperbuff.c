#include <windows.h>

#include "test_assert.h"

int main(void) {
	char text[] = "ab";
	WCHAR buffer[] = {'a', 'B', 0, 'c', 'x'};
	DWORD result;

	result = CharUpperBuffW(buffer, 4);
	TEST_CHECK_EQ(4, result);
	TEST_CHECK_EQ('A', buffer[0]);
	TEST_CHECK_EQ('B', buffer[1]);
	TEST_CHECK_EQ(0, buffer[2]);
	TEST_CHECK_EQ('C', buffer[3]);
	TEST_CHECK_EQ('x', buffer[4]);
	TEST_CHECK_EQ(0, CharUpperBuffW(NULL, 1));

	TEST_CHECK(CharNextA(text) == text + 1);
	TEST_CHECK(CharNextA(text + 1) == text + 2);
	TEST_CHECK(CharNextA(text + 2) == text + 2);
	return 0;
}
