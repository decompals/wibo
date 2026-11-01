#include "test_assert.h"

#include <windows.h>

int main(void) {
	TEST_CHECK(IsValidLocaleName(L"en-US"));

	WCHAR upper[16] = {0};
	int length = LCMapStringEx(L"en-US", LCMAP_UPPERCASE, L"abc", 4, upper, 16, NULL, NULL, 0);
	TEST_CHECK_EQ(4, length);
	TEST_CHECK(wcscmp(upper, L"ABC") == 0);

	TEST_CHECK_EQ(4, LCMapStringEx(L"en-US", LCMAP_UPPERCASE, L"abc", 4, NULL, 0, NULL, NULL, 0));

	TEST_CHECK_EQ(CSTR_EQUAL, CompareStringEx(L"en-US", 0, L"abc", -1, L"abc", -1, NULL, NULL, 0));
	TEST_CHECK_EQ(CSTR_LESS_THAN, CompareStringEx(L"en-US", 0, L"abc", -1, L"abd", -1, NULL, NULL, 0));
	TEST_CHECK_EQ(CSTR_GREATER_THAN, CompareStringEx(L"en-US", 0, L"abd", -1, L"abc", -1, NULL, NULL, 0));
	TEST_CHECK_EQ(CSTR_EQUAL, CompareStringEx(L"en-US", NORM_IGNORECASE, L"ABC", -1, L"abc", -1, NULL, NULL, 0));
	return 0;
}
