#include <windows.h>

#include "test_assert.h"

static void test_char_lower_buff_a(void) {
	char buffer[] = "WiBo-42";
	DWORD converted = CharLowerBuffA(buffer, (DWORD)strlen(buffer));
	TEST_CHECK_EQ(strlen("WiBo-42"), converted);
	TEST_CHECK(strcmp(buffer, "wibo-42") == 0);
}

static void test_char_lower_buff_w(void) {
	WCHAR buffer[] = L"WiBo-42";
	DWORD converted = CharLowerBuffW(buffer, (DWORD)wcslen(buffer));
	TEST_CHECK_EQ(wcslen(L"WiBo-42"), converted);
	TEST_CHECK(wcscmp(buffer, L"wibo-42") == 0);
}

static void test_char_upper_buff_w(void) {
	WCHAR buffer[] = L"WiBo-42";
	DWORD converted = CharUpperBuffW(buffer, (DWORD)wcslen(buffer));
	TEST_CHECK_EQ(wcslen(L"WiBo-42"), converted);
	TEST_CHECK(wcscmp(buffer, L"WIBO-42") == 0);
}

static void test_buffers_respect_length(void) {
	char buffer[] = "ABCD";
	TEST_CHECK_EQ(2u, CharLowerBuffA(buffer, 2));
	TEST_CHECK(strcmp(buffer, "abCD") == 0);

	WCHAR wide[] = L"abcd";
	TEST_CHECK_EQ(2u, CharUpperBuffW(wide, 2));
	TEST_CHECK(wcscmp(wide, L"ABcd") == 0);
}

static void test_char_to_oem_buff(void) {
	static const char source[] = "wibo-42";
	char oem[sizeof(source)];
	memset(oem, 0xCC, sizeof(oem));
	TEST_CHECK(CharToOemBuffA(source, oem, (DWORD)sizeof(source)));
	TEST_CHECK(memcmp(oem, source, sizeof(source)) == 0);
}

int main(void) {
	test_char_lower_buff_a();
	test_char_lower_buff_w();
	test_char_upper_buff_w();
	test_buffers_respect_length();
	test_char_to_oem_buff();
	return 0;
}
