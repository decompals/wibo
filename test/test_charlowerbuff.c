#include <windows.h>

#include "test_assert.h"

int main(void) {
	char buffer[] = {'A', 'b', 0, 'C', 'X'};
	DWORD result;

	result = CharLowerBuffA(buffer, 4);
	TEST_CHECK_EQ(4, result);
	TEST_CHECK_EQ('a', buffer[0]);
	TEST_CHECK_EQ('b', buffer[1]);
	TEST_CHECK_EQ(0, buffer[2]);
	TEST_CHECK_EQ('c', buffer[3]);
	TEST_CHECK_EQ('X', buffer[4]);
	TEST_CHECK_EQ(0, CharLowerBuffA(buffer, 0));
	TEST_CHECK_EQ('X', buffer[4]);
	return 0;
}
