#include <windows.h>

#include <oleauto.h>

#include <stdint.h>

#include "test_assert.h"

static DWORD bstr_byte_length(BSTR value) { return ((const DWORD *)value)[-1]; }

static void test_alloc_copies_and_terminates(void) {
	static const OLECHAR kSource[] = L"wibo";
	BSTR value = SysAllocStringLen(kSource, 4);
	TEST_CHECK_MSG(value != NULL, "SysAllocStringLen failed");
	TEST_CHECK_EQ(8u, bstr_byte_length(value));
	TEST_CHECK(memcmp(value, kSource, 8) == 0);
	TEST_CHECK_EQ(0, value[4]);
	SysFreeString(value);
}

// Windows leaves the characters uninitialized; only the terminator is set.
static void test_alloc_without_source_is_terminated(void) {
	BSTR value = SysAllocStringLen(NULL, 3);
	TEST_CHECK_MSG(value != NULL, "SysAllocStringLen(NULL) failed");
	TEST_CHECK_EQ(6u, bstr_byte_length(value));
	TEST_CHECK_EQ(0, value[3]);
	SysFreeString(value);
}

static void test_alloc_empty(void) {
	BSTR value = SysAllocStringLen(NULL, 0);
	TEST_CHECK_MSG(value != NULL, "SysAllocStringLen(NULL, 0) failed");
	TEST_CHECK_EQ(0u, bstr_byte_length(value));
	TEST_CHECK_EQ(0, value[0]);
	SysFreeString(value);
}

static void test_free_null_is_safe(void) { SysFreeString(NULL); }

int main(void) {
	test_alloc_copies_and_terminates();
	test_alloc_without_source_is_terminated();
	test_alloc_empty();
	test_free_null_is_safe();
	return 0;
}
