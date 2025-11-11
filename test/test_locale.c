#include <windows.h>

#include <stdlib.h>
#include <wchar.h>

#include "test_assert.h"

static void test_getlocaleinfoex_matches_getlocaleinfow(void) {
	int required_ex = GetLocaleInfoEx(NULL, LOCALE_SENGCOUNTRY, NULL, 0);
	TEST_CHECK(required_ex > 0);

	WCHAR *buffer_ex = (WCHAR *)malloc((size_t)required_ex * sizeof(WCHAR));
	TEST_CHECK(buffer_ex != NULL);

	int written_ex = GetLocaleInfoEx(NULL, LOCALE_SENGCOUNTRY, buffer_ex, required_ex);
	TEST_CHECK(written_ex > 0);

	LCID lcid = GetUserDefaultLCID();
	int required_w = GetLocaleInfoW(lcid, LOCALE_SENGCOUNTRY, NULL, 0);
	TEST_CHECK(required_w > 0);

	WCHAR *buffer_w = (WCHAR *)malloc((size_t)required_w * sizeof(WCHAR));
	TEST_CHECK(buffer_w != NULL);
	int written_w = GetLocaleInfoW(lcid, LOCALE_SENGCOUNTRY, buffer_w, required_w);
	TEST_CHECK(written_w > 0);

	TEST_CHECK_EQ(required_ex, written_ex);
	TEST_CHECK_EQ(required_w, written_w);
	TEST_CHECK_EQ(required_ex, required_w);
	TEST_CHECK(wcscmp(buffer_ex, buffer_w) == 0);

	free(buffer_w);
	free(buffer_ex);
}

static void test_getlocaleinfoex_errors(void) {
	WCHAR buffer[16];

	SetLastError(0);
	TEST_CHECK(!GetLocaleInfoEx(NULL, LOCALE_SENGCOUNTRY, buffer, -1));
	TEST_CHECK_EQ(ERROR_INSUFFICIENT_BUFFER, GetLastError());

	SetLastError(0);
	TEST_CHECK(!GetLocaleInfoEx(NULL, LOCALE_SENGCOUNTRY, buffer, 1));
	TEST_CHECK_EQ(ERROR_INSUFFICIENT_BUFFER, GetLastError());
}

static void test_getlocaleinfoex_named_locale(void) {
	int required = GetLocaleInfoEx(L"en-US", LOCALE_SENGLANGUAGE, NULL, 0);
	TEST_CHECK(required > 0);

	WCHAR *buffer = (WCHAR *)malloc((size_t)required * sizeof(WCHAR));
	TEST_CHECK(buffer != NULL);

	TEST_CHECK(GetLocaleInfoEx(L"en-US", LOCALE_SENGLANGUAGE, buffer, required) > 0);
	free(buffer);
}

int main(void) {
	test_getlocaleinfoex_matches_getlocaleinfow();
	test_getlocaleinfoex_errors();
	test_getlocaleinfoex_named_locale();
	return 0;
}
