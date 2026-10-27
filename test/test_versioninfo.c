#include <windows.h>

#include <stdio.h>

#include "test_assert.h"

static OSVERSIONINFOEXW current_version(void) {
	OSVERSIONINFOEXW info;
	memset(&info, 0, sizeof(info));
	info.dwOSVersionInfoSize = sizeof(info);
	TEST_CHECK_MSG(GetVersionExW((OSVERSIONINFOW *)&info), "GetVersionExW failed: %lu", GetLastError());
	return info;
}

static BOOL check_major(DWORD major, BYTE condition) {
	OSVERSIONINFOEXW wanted;
	memset(&wanted, 0, sizeof(wanted));
	wanted.dwOSVersionInfoSize = sizeof(wanted);
	wanted.dwMajorVersion = major;
	ULONGLONG mask = VerSetConditionMask(0, VER_MAJORVERSION, condition);
	return VerifyVersionInfoW(&wanted, VER_MAJORVERSION, mask);
}

static void test_major_version_comparisons(void) {
	OSVERSIONINFOEXW info = current_version();
	TEST_CHECK(check_major(info.dwMajorVersion, VER_EQUAL));
	TEST_CHECK(check_major(info.dwMajorVersion, VER_GREATER_EQUAL));
	TEST_CHECK(check_major(info.dwMajorVersion, VER_LESS_EQUAL));
	// No VER_GREATER or VER_LESS at the same major: Windows 10 returns TRUE for
	// both, Wine returns FALSE.

	TEST_CHECK(check_major(info.dwMajorVersion - 1, VER_GREATER));
	TEST_CHECK(!check_major(info.dwMajorVersion + 1, VER_GREATER_EQUAL));

	SetLastError(0xdeadbeef);
	TEST_CHECK(!check_major(info.dwMajorVersion + 1, VER_EQUAL));
	TEST_CHECK_EQ(ERROR_OLD_WIN_VERSION, GetLastError());
}

static void test_condition_mask_slots(void) {
	ULONGLONG mask = VerSetConditionMask(0, VER_MAJORVERSION, VER_GREATER_EQUAL);
	TEST_CHECK(mask != 0);
	ULONGLONG both = VerSetConditionMask(mask, VER_MINORVERSION, VER_GREATER_EQUAL);
	TEST_CHECK(both != mask);
	TEST_CHECK_U64_EQ(both, VerSetConditionMask(both, VER_MINORVERSION, VER_GREATER_EQUAL));
	TEST_CHECK_U64_EQ(0ull, VerSetConditionMask(0, 0, VER_EQUAL));
}

static void test_native_system_info_matches(void) {
	SYSTEM_INFO native;
	SYSTEM_INFO current;
	memset(&native, 0, sizeof(native));
	memset(&current, 0, sizeof(current));
	GetNativeSystemInfo(&native);
	GetSystemInfo(&current);
	TEST_CHECK(native.dwPageSize != 0);
	TEST_CHECK_EQ(current.dwPageSize, native.dwPageSize);
	TEST_CHECK_EQ(current.dwAllocationGranularity, native.dwAllocationGranularity);
	TEST_CHECK_EQ(current.dwNumberOfProcessors, native.dwNumberOfProcessors);
}

int main(void) {
	test_major_version_comparisons();
	test_condition_mask_slots();
	test_native_system_info_matches();
	return 0;
}
