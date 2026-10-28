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

static void test_thread_locale_roundtrip(void) {
	LCID original = GetThreadLocale();
	TEST_CHECK(original != 0);
	TEST_CHECK(SetThreadLocale(MAKELCID(MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), SORT_DEFAULT)));
	TEST_CHECK_EQ(MAKELCID(MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), SORT_DEFAULT), GetThreadLocale());
	TEST_CHECK(SetThreadLocale(original));
	TEST_CHECK_EQ(original, GetThreadLocale());
}

static void test_thread_ui_language(void) {
	LANGID ui = GetThreadUILanguage();
	TEST_CHECK(ui != 0);
}

static void test_preferred_ui_languages(void) {
	ULONG count = 0;
	ULONG size = 0;
	TEST_CHECK_MSG(GetThreadPreferredUILanguages(MUI_LANGUAGE_NAME, &count, NULL, &size),
				   "GetThreadPreferredUILanguages(size) failed: %lu", GetLastError());
	TEST_CHECK(size > 1);

	WCHAR *buffer = (WCHAR *)malloc(size * sizeof(WCHAR));
	TEST_CHECK(buffer != NULL);
	ULONG capacity = size;
	TEST_CHECK_MSG(GetThreadPreferredUILanguages(MUI_LANGUAGE_NAME, &count, buffer, &capacity),
				   "GetThreadPreferredUILanguages failed: %lu", GetLastError());
	TEST_CHECK(count >= 1);
	TEST_CHECK(wcslen(buffer) > 0);
	TEST_CHECK_EQ(0, buffer[capacity - 1]);
	free(buffer);

	ULONG id_size = 0;
	TEST_CHECK(GetThreadPreferredUILanguages(MUI_LANGUAGE_ID, &count, NULL, &id_size));
	WCHAR *ids = (WCHAR *)malloc(id_size * sizeof(WCHAR));
	TEST_CHECK(ids != NULL);
	ULONG id_capacity = id_size;
	TEST_CHECK(GetThreadPreferredUILanguages(MUI_LANGUAGE_ID, &count, ids, &id_capacity));
	TEST_CHECK_EQ(4u, wcslen(ids));
	free(ids);

	// No flag behaves like MUI_LANGUAGE_NAME.
	ULONG default_size = 0;
	TEST_CHECK(GetThreadPreferredUILanguages(0, &count, NULL, &default_size));
	TEST_CHECK_EQ(size, default_size);

	ULONG set_count = 0;
	TEST_CHECK(SetThreadPreferredUILanguages(MUI_LANGUAGE_NAME, L"en-US\0", &set_count));
}

static void test_compare_string_ordinal(void) {
	TEST_CHECK_EQ(CSTR_EQUAL, CompareStringOrdinal(L"wibo", -1, L"wibo", -1, FALSE));
	TEST_CHECK_EQ(CSTR_EQUAL, CompareStringOrdinal(L"WIBO", -1, L"wibo", -1, TRUE));
	TEST_CHECK_EQ(CSTR_LESS_THAN, CompareStringOrdinal(L"WIBO", -1, L"wibo", -1, FALSE));
	TEST_CHECK_EQ(CSTR_LESS_THAN, CompareStringOrdinal(L"wib", -1, L"wibo", -1, FALSE));
	TEST_CHECK_EQ(CSTR_GREATER_THAN, CompareStringOrdinal(L"wibo", -1, L"wib", -1, FALSE));
	TEST_CHECK_EQ(CSTR_EQUAL, CompareStringOrdinal(L"wibo", 3, L"wibx", 3, FALSE));
}

static int g_era_count;

static BOOL CALLBACK era_callback(LPWSTR value) {
	TEST_CHECK(value != NULL);
	TEST_CHECK(wcslen(value) > 0);
	++g_era_count;
	return TRUE;
}

static void test_enum_calendar_info(void) {
	g_era_count = 0;
	TEST_CHECK_MSG(EnumCalendarInfoW(era_callback, LOCALE_USER_DEFAULT, CAL_GREGORIAN, CAL_SERASTRING),
				   "EnumCalendarInfoW(CAL_SERASTRING) failed: %lu", GetLastError());
	TEST_CHECK(g_era_count >= 1);

	g_era_count = 0;
	TEST_CHECK_MSG(EnumCalendarInfoW(era_callback, LOCALE_USER_DEFAULT, CAL_GREGORIAN, CAL_IYEAROFFSETRANGE),
				   "EnumCalendarInfoW(CAL_IYEAROFFSETRANGE) failed: %lu", GetLastError());
	TEST_CHECK(g_era_count >= 1);
}

int main(void) {
	test_getlocaleinfoex_matches_getlocaleinfow();
	test_getlocaleinfoex_errors();
	test_getlocaleinfoex_named_locale();
	test_thread_locale_roundtrip();
	test_thread_ui_language();
	test_preferred_ui_languages();
	test_compare_string_ordinal();
	test_enum_calendar_info();
	return 0;
}
