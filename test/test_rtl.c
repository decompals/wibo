#include <windows.h>
#include <string.h>
#include <winternl.h>

#include "test_assert.h"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif

typedef NTSTATUS(WINAPI *RtlGetVersionFn)(PRTL_OSVERSIONINFOW);

static RtlGetVersionFn load_rtl_get_version(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        ntdll = LoadLibraryW(L"ntdll.dll");
    }
    TEST_CHECK(ntdll != NULL);
    FARPROC proc = GetProcAddress(ntdll, "RtlGetVersion");
    TEST_CHECK(proc != NULL);
    RtlGetVersionFn fn = NULL;
    TEST_CHECK(sizeof(fn) == sizeof(proc));
    memcpy(&fn, &proc, sizeof(fn));
    return fn;
}

static void test_basic_version(RtlGetVersionFn rtl_get_version) {
    RTL_OSVERSIONINFOW info;
    memset(&info, 0xCC, sizeof(info));
    info.dwOSVersionInfoSize = sizeof(info);

    NTSTATUS status = rtl_get_version(&info);
    TEST_CHECK_EQ((NTSTATUS)STATUS_SUCCESS, status);
    TEST_CHECK_EQ(sizeof(info), info.dwOSVersionInfoSize);
    TEST_CHECK_EQ(6u, info.dwMajorVersion);
    TEST_CHECK_EQ(2u, info.dwMinorVersion);
    TEST_CHECK_EQ(0u, info.dwBuildNumber);
    TEST_CHECK_EQ(2u, info.dwPlatformId);
    TEST_CHECK_EQ(0, info.szCSDVersion[0]);
}

static void test_extended_version(RtlGetVersionFn rtl_get_version) {
    RTL_OSVERSIONINFOEXW info;
    memset(&info, 0xCC, sizeof(info));
    info.dwOSVersionInfoSize = sizeof(info);

    NTSTATUS status = rtl_get_version((PRTL_OSVERSIONINFOW)&info);
    TEST_CHECK_EQ((NTSTATUS)STATUS_SUCCESS, status);
    TEST_CHECK_EQ(sizeof(info), info.dwOSVersionInfoSize);
    TEST_CHECK_EQ(6u, info.dwMajorVersion);
    TEST_CHECK_EQ(2u, info.dwMinorVersion);
    TEST_CHECK_EQ(0u, info.dwBuildNumber);
    TEST_CHECK_EQ(2u, info.dwPlatformId);
    TEST_CHECK_EQ(1u, info.wProductType);
    TEST_CHECK_EQ(0u, info.wServicePackMajor);
    TEST_CHECK_EQ(0u, info.wServicePackMinor);
    TEST_CHECK_EQ(0u, info.wSuiteMask);
    TEST_CHECK_EQ(0u, info.wReserved);
}

static void test_invalid_size(RtlGetVersionFn rtl_get_version) {
    RTL_OSVERSIONINFOW info;
    memset(&info, 0xCC, sizeof(info));
    info.dwOSVersionInfoSize = sizeof(info) - 4;

    NTSTATUS status = rtl_get_version(&info);
    TEST_CHECK_EQ((NTSTATUS)STATUS_INVALID_PARAMETER, status);
}

int main(void) {
    RtlGetVersionFn rtl_get_version = load_rtl_get_version();
    test_basic_version(rtl_get_version);
    test_extended_version(rtl_get_version);
    test_invalid_size(rtl_get_version);
    return 0;
}
