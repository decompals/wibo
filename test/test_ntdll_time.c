#include <stdint.h>
#include <string.h>
#include <windows.h>
#include <winternl.h>

#include "test_assert.h"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

static const ULONGLONG kUnixEpochAsFileTime = 116444736000000000ULL;
static const ULONGLONG kHundredNsPerSecond = 10000000ULL;

typedef NTSTATUS(WINAPI *NtQuerySystemTimeFn)(PLARGE_INTEGER SystemTime);
typedef BOOLEAN(WINAPI *RtlTimeToSecondsSince1970Fn)(PLARGE_INTEGER Time, PULONG ElapsedSeconds);

static struct {
    NtQuerySystemTimeFn query_system_time;
    RtlTimeToSecondsSince1970Fn time_to_seconds;
} gFns;

static FARPROC load_ntdll_proc(const char *name) {
    static HMODULE ntdll;
    if (!ntdll) {
        ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) {
            ntdll = LoadLibraryW(L"ntdll.dll");
        }
    }
    TEST_CHECK(ntdll != NULL);
    FARPROC proc = GetProcAddress(ntdll, name);
    TEST_CHECK(proc != NULL);
    return proc;
}

static void ensure_functions_loaded(void) {
    if (gFns.query_system_time) {
        return;
    }

    FARPROC proc = load_ntdll_proc("NtQuerySystemTime");
    TEST_CHECK(sizeof(gFns.query_system_time) == sizeof(proc));
    memcpy(&gFns.query_system_time, &proc, sizeof(gFns.query_system_time));

    proc = load_ntdll_proc("RtlTimeToSecondsSince1970");
    TEST_CHECK(sizeof(gFns.time_to_seconds) == sizeof(proc));
    memcpy(&gFns.time_to_seconds, &proc, sizeof(gFns.time_to_seconds));
}

static ULONGLONG filetime_to_u64(const FILETIME *ft) {
    ULARGE_INTEGER li;
    li.LowPart = ft->dwLowDateTime;
    li.HighPart = ft->dwHighDateTime;
    return li.QuadPart;
}

static void test_nt_query_system_time_matches_filetime(void) {
    LARGE_INTEGER system_time = {.QuadPart = 0};
    NTSTATUS status = gFns.query_system_time(&system_time);
    TEST_CHECK_EQ(STATUS_SUCCESS, status);

    FILETIME ft = {0};
    GetSystemTimeAsFileTime(&ft);
    ULONGLONG api_time = filetime_to_u64(&ft);
    ULONGLONG query_time = (ULONGLONG)system_time.QuadPart;
    ULONGLONG delta = (api_time > query_time) ? (api_time - query_time) : (query_time - api_time);
    TEST_CHECK_MSG(delta < 1000000ULL, "NtQuerySystemTime skew too large: %llu", (unsigned long long)delta);
}

static void test_nt_query_system_time_null(void) {
    NTSTATUS status = gFns.query_system_time(NULL);
    TEST_CHECK_EQ((ULONG)STATUS_ACCESS_VIOLATION, (ULONG)status);
}

static void test_rtl_time_to_seconds_success(void) {
    LARGE_INTEGER system_time = {.QuadPart = 0};
    TEST_CHECK_EQ(STATUS_SUCCESS, gFns.query_system_time(&system_time));

    ULONG seconds = 0;
    TEST_CHECK(gFns.time_to_seconds(&system_time, &seconds));
    ULONGLONG expected = ((ULONGLONG)system_time.QuadPart - kUnixEpochAsFileTime) / kHundredNsPerSecond;
    TEST_CHECK_EQ(expected, seconds);
}

static void test_rtl_time_to_seconds_invalid_inputs(void) {
    LARGE_INTEGER before_epoch = {.QuadPart = (LONGLONG)(kUnixEpochAsFileTime - kHundredNsPerSecond)};
    ULONG seconds = 0;
    TEST_CHECK_EQ(FALSE, gFns.time_to_seconds(&before_epoch, &seconds));

    LARGE_INTEGER beyond_range = {
        .QuadPart = (LONGLONG)(kUnixEpochAsFileTime + (0x1'00000000ULL * kHundredNsPerSecond))};
    TEST_CHECK_EQ(FALSE, gFns.time_to_seconds(&beyond_range, &seconds));
}

int main(void) {
    ensure_functions_loaded();
    TEST_CHECK(gFns.query_system_time);
    TEST_CHECK(gFns.time_to_seconds);

    test_nt_query_system_time_matches_filetime();
    test_nt_query_system_time_null();
    test_rtl_time_to_seconds_success();
    test_rtl_time_to_seconds_invalid_inputs();
    return 0;
}
