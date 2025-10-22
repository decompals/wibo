#include <objbase.h>
#include <string.h>
#include <windows.h>

#include "test_assert.h"

static int guid_equals(const GUID *a, const GUID *b) { return memcmp(a, b, sizeof(GUID)) == 0; }

static GUID make_guid(unsigned int d1, unsigned short d2, unsigned short d3, unsigned char d40, unsigned char d41,
					  unsigned char d42, unsigned char d43, unsigned char d44, unsigned char d45, unsigned char d46,
					  unsigned char d47) {
	GUID guid;
	guid.Data1 = d1;
	guid.Data2 = d2;
	guid.Data3 = d3;
	guid.Data4[0] = d40;
	guid.Data4[1] = d41;
	guid.Data4[2] = d42;
	guid.Data4[3] = d43;
	guid.Data4[4] = d44;
	guid.Data4[5] = d45;
	guid.Data4[6] = d46;
	guid.Data4[7] = d47;
	return guid;
}

static void test_null_string_returns_guid_null(void) {
	GUID guid;
	memset(&guid, 0xCC, sizeof(guid));

	HRESULT hr = CLSIDFromString(NULL, &guid);
	TEST_CHECK_EQ(S_OK, hr);
	GUID expected = make_guid(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	TEST_CHECK(guid_equals(&expected, &guid));
}

static void test_braced_guid_parses_iunknown(void) {
	GUID guid;
	memset(&guid, 0xCC, sizeof(guid));

	HRESULT hr = CLSIDFromString(L"{00000000-0000-0000-C000-000000000046}", &guid);
	TEST_CHECK_EQ(S_OK, hr);
	GUID expected = make_guid(0x00000000, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46);
	TEST_CHECK(guid_equals(&expected, &guid));
}

static void test_guid_without_braces_is_rejected(void) {
	GUID guid;
	memset(&guid, 0xCC, sizeof(guid));

	HRESULT hr = CLSIDFromString(L"6B29FC40-CA47-1067-B31D-00DD010662DA", &guid);
	TEST_CHECK_EQ(CO_E_CLASSSTRING, hr);
}

static void test_guid_with_spacing_is_rejected(void) {
	GUID guid;
	memset(&guid, 0xCC, sizeof(guid));

	HRESULT hr = CLSIDFromString(L"  {6B29FC40-CA47-1067-B31D-00DD010662DA}\t", &guid);
	TEST_CHECK_EQ(CO_E_CLASSSTRING, hr);
}

static void test_invalid_string_returns_error(void) {
	GUID guid;
	memset(&guid, 0xCC, sizeof(guid));

	HRESULT hr = CLSIDFromString(L"not-a-guid", &guid);
	TEST_CHECK_EQ(CO_E_CLASSSTRING, hr);
}

static void test_null_output_pointer_returns_invalid_arg(void) {
	HRESULT hr = CLSIDFromString(L"{00000000-0000-0000-C000-000000000046}", NULL);
	TEST_CHECK_EQ(E_INVALIDARG, hr);
}

int main(void) {
	test_null_string_returns_guid_null();
	test_braced_guid_parses_iunknown();
	test_guid_without_braces_is_rejected();
	test_guid_with_spacing_is_rejected();
	test_invalid_string_returns_error();
	test_null_output_pointer_returns_invalid_arg();
	return 0;
}
