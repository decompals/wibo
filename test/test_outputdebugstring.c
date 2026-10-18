#include <windows.h>

#include "test_assert.h"

int main(void) {
	char text[] = "debug output";

	OutputDebugStringA(text);
	TEST_CHECK_STR_EQ("debug output", text);
	OutputDebugStringA("");
	OutputDebugStringA(NULL);
	return 0;
}
