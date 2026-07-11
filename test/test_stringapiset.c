#include "test_assert.h"

#include <windows.h>

int main(void) {
	char narrow[8];
	WCHAR wide[8];

	SetLastError(0);
	TEST_CHECK_EQ(0, WideCharToMultiByte(CP_ACP, 0, NULL, -1, narrow, sizeof(narrow), NULL, NULL));
	TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());

	SetLastError(0);
	TEST_CHECK_EQ(0, WideCharToMultiByte(CP_ACP, 0, L"x", 0, narrow, sizeof(narrow), NULL, NULL));
	TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());

	SetLastError(0);
	TEST_CHECK_EQ(0, WideCharToMultiByte(CP_ACP, 0, L"x", -1, NULL, sizeof(narrow), NULL, NULL));
	TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());

	BOOL usedDefault = TRUE;
	TEST_CHECK_EQ(2, WideCharToMultiByte(CP_ACP, 0, L"x", -1, NULL, 0, NULL, &usedDefault));
	TEST_CHECK_EQ(FALSE, usedDefault);

	SetLastError(0);
	TEST_CHECK_EQ(0, MultiByteToWideChar(CP_ACP, 0, NULL, -1, wide, sizeof(wide) / sizeof(wide[0])));
	TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());

	SetLastError(0);
	TEST_CHECK_EQ(0, MultiByteToWideChar(CP_ACP, 0, "x", 0, wide, sizeof(wide) / sizeof(wide[0])));
	TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());

	SetLastError(0);
	TEST_CHECK_EQ(0, MultiByteToWideChar(CP_ACP, 0, "x", -1, NULL, sizeof(wide) / sizeof(wide[0])));
	TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());

	return 0;
}
