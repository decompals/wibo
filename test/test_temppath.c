#include "test_assert.h"

#include <string.h>
#include <windows.h>

int main(void) {
	char buffer[MAX_PATH];
	DWORD len = GetTempPathA(sizeof(buffer), buffer);
	TEST_CHECK(len > 0 && len < sizeof(buffer));
	TEST_CHECK_EQ(len, strlen(buffer));
	TEST_CHECK_EQ('\\', buffer[len - 1]);

	char too_small[MAX_PATH];
	memset(too_small, 0xCC, sizeof(too_small));
	DWORD required = GetTempPathA(len, too_small);
	TEST_CHECK_EQ(len + 1, required);

	return 0;
}
