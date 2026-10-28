#include "test_assert.h"

#include <string.h>
#include <windows.h>
#include <oleauto.h>

static UINT prefixBytes(BSTR bstr) { return ((const UINT *)bstr)[-1]; }

static void test_alloc_basic(void) {
	static const WCHAR kText[] = L"hello world";
	BSTR bstr = SysAllocString(kText);
	TEST_CHECK(bstr != NULL);
	TEST_CHECK_EQ(11, SysStringLen(bstr));
	TEST_CHECK_EQ(22, prefixBytes(bstr));
	TEST_CHECK(memcmp(bstr, kText, sizeof(kText)) == 0);
	TEST_CHECK_EQ(0, bstr[11]);
	SysFreeString(bstr);
}

static void test_alloc_empty(void) {
	BSTR bstr = SysAllocString(L"");
	TEST_CHECK(bstr != NULL);
	TEST_CHECK_EQ(0, SysStringLen(bstr));
	TEST_CHECK_EQ(0, prefixBytes(bstr));
	TEST_CHECK_EQ(0, bstr[0]);
	SysFreeString(bstr);
}

static void test_null_handling(void) {
	TEST_CHECK(SysAllocString(NULL) == NULL);
	TEST_CHECK_EQ(0, SysStringLen(NULL));
	SysFreeString(NULL);
}

static void test_independent_allocations(void) {
	BSTR a = SysAllocString(L"first");
	BSTR b = SysAllocString(L"second string");
	TEST_CHECK(a != NULL && b != NULL && a != b);
	TEST_CHECK_EQ(5, SysStringLen(a));
	TEST_CHECK_EQ(13, SysStringLen(b));
	SysFreeString(a);
	TEST_CHECK(memcmp(b, L"second string", sizeof(L"second string")) == 0);
	SysFreeString(b);
}

// MSVC import libraries bind these by ordinal, not by name.
static void test_ordinal_exports(void) {
	HMODULE mod = GetModuleHandleA("oleaut32.dll");
	TEST_CHECK(mod != NULL);
	TEST_CHECK(GetProcAddress(mod, MAKEINTRESOURCEA(2)) == GetProcAddress(mod, "SysAllocString"));
	TEST_CHECK(GetProcAddress(mod, MAKEINTRESOURCEA(6)) == GetProcAddress(mod, "SysFreeString"));
	TEST_CHECK(GetProcAddress(mod, MAKEINTRESOURCEA(7)) == GetProcAddress(mod, "SysStringLen"));
	TEST_CHECK(GetProcAddress(mod, "SysAllocString") != NULL);
}

int main(void) {
	test_alloc_basic();
	test_alloc_empty();
	test_null_handling();
	test_independent_allocations();
	test_ordinal_exports();
	return 0;
}
