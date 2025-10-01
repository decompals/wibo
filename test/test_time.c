#include <windows.h>
#include <stdint.h>
#include <stdio.h>

#include "test_assert.h"

static uint64_t filetime_to_u64(const FILETIME *ft) {
    ULARGE_INTEGER li;
    li.LowPart = ft->dwLowDateTime;
    li.HighPart = ft->dwHighDateTime;
    return li.QuadPart;
}

static FILETIME u64_to_filetime(uint64_t value) {
    ULARGE_INTEGER li;
    li.QuadPart = value;
    FILETIME ft;
    ft.dwLowDateTime = li.LowPart;
    ft.dwHighDateTime = li.HighPart;
    return ft;
}

static uint64_t abs_u64_diff(uint64_t a, uint64_t b) {
    return (a > b) ? (a - b) : (b - a);
}

static void test_systemtime_roundtrip(void) {
    SYSTEMTIME st = {
        .wYear = 2023,
        .wMonth = 7,
        .wDay = 15,
        .wHour = 12,
        .wMinute = 34,
        .wSecond = 56,
        .wMilliseconds = 789
    };

    FILETIME ft;
    TEST_CHECK(SystemTimeToFileTime(&st, &ft));

    SYSTEMTIME converted = {0};
    TEST_CHECK(FileTimeToSystemTime(&ft, &converted));

    TEST_CHECK_EQ(st.wYear, converted.wYear);
    TEST_CHECK_EQ(st.wMonth, converted.wMonth);
    TEST_CHECK_EQ(st.wDay, converted.wDay);
    TEST_CHECK_EQ(st.wHour, converted.wHour);
    TEST_CHECK_EQ(st.wMinute, converted.wMinute);
    TEST_CHECK_EQ(st.wSecond, converted.wSecond);
    TEST_CHECK_EQ(st.wMilliseconds, converted.wMilliseconds);

    SetLastError(0);
    SYSTEMTIME invalid = st;
    invalid.wMonth = 13;
    TEST_CHECK(!SystemTimeToFileTime(&invalid, &ft));
    TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());
}

static void test_filetime_known_timestamp(void) {
    /* 2023-01-01 00:00:00 UTC */
    const uint64_t expected_ticks = 133170048000000000ULL;
    FILETIME ft = u64_to_filetime(expected_ticks);

    SYSTEMTIME st = {0};
    TEST_CHECK(FileTimeToSystemTime(&ft, &st));
    TEST_CHECK_EQ(2023, st.wYear);
    TEST_CHECK_EQ(1, st.wMonth);
    TEST_CHECK_EQ(1, st.wDay);
    TEST_CHECK_EQ(0, st.wHour);
    TEST_CHECK_EQ(0, st.wMinute);
    TEST_CHECK_EQ(0, st.wSecond);
    TEST_CHECK_EQ(0, st.wMilliseconds);

    FILETIME back;
    TEST_CHECK(SystemTimeToFileTime(&st, &back));
    TEST_CHECK_U64_EQ(expected_ticks, filetime_to_u64(&back));
}

static void test_getsystemtimeasfiletime(void) {
    FILETIME from_api;
    GetSystemTimeAsFileTime(&from_api);

    SYSTEMTIME sys_now;
    GetSystemTime(&sys_now);
    FILETIME from_system;
    TEST_CHECK(SystemTimeToFileTime(&sys_now, &from_system));

    uint64_t delta = abs_u64_diff(filetime_to_u64(&from_api), filetime_to_u64(&from_system));
    /* allow 1 second of skew between calls */
    TEST_CHECK_MSG(delta < 10000000ULL, "GetSystemTimeAsFileTime skew too large: %llu", (unsigned long long)delta);
}

static void test_gettickcount_progresses(void) {
    DWORD start = GetTickCount();
    Sleep(60);
    DWORD end = GetTickCount();
    DWORD diff = end - start;

    TEST_CHECK_MSG(diff >= 40, "GetTickCount diff too small: %lu", (unsigned long)diff);
    TEST_CHECK_MSG(diff <= 5000, "GetTickCount diff too large: %lu", (unsigned long)diff);
}

static void test_setfiletime_roundtrip(void) {
    char temp_path[MAX_PATH];
    char temp_file[MAX_PATH];

    DWORD path_len = GetTempPathA(sizeof(temp_path), temp_path);
    TEST_CHECK(path_len > 0 && path_len < sizeof(temp_path));

    UINT unique = GetTempFileNameA(temp_path, "TST", 0, temp_file);
    TEST_CHECK(unique != 0);

    HANDLE handle = CreateFileA(temp_file, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    TEST_CHECK(handle != INVALID_HANDLE_VALUE);

    FILETIME original_creation = {0}, original_access = {0}, original_write = {0};
    TEST_CHECK(GetFileTime(handle, &original_creation, &original_access, &original_write));

    SYSTEMTIME desired = {
        .wYear = 2022,
        .wMonth = 12,
        .wDay = 31,
        .wHour = 5,
        .wMinute = 45,
        .wSecond = 12,
        .wMilliseconds = 123
    };
    FILETIME desired_ft;
    TEST_CHECK(SystemTimeToFileTime(&desired, &desired_ft));

    TEST_CHECK(SetFileTime(handle, NULL, NULL, &desired_ft));

    FILETIME updated_creation = {0}, updated_access = {0}, updated_write = {0};
    TEST_CHECK(GetFileTime(handle, &updated_creation, &updated_access, &updated_write));
    TEST_CHECK_U64_EQ(filetime_to_u64(&desired_ft), filetime_to_u64(&updated_write));

    FILETIME zero = {0, 0};
    TEST_CHECK(SetFileTime(handle, NULL, &zero, NULL));

    FILETIME final_creation = {0}, final_access = {0}, final_write = {0};
    TEST_CHECK(GetFileTime(handle, &final_creation, &final_access, &final_write));
    TEST_CHECK_U64_EQ(filetime_to_u64(&updated_access), filetime_to_u64(&final_access));
    TEST_CHECK_U64_EQ(filetime_to_u64(&updated_write), filetime_to_u64(&final_write));

    CloseHandle(handle);
    DeleteFileA(temp_file);
}

static void test_local_filetime_conversions(void) {
    /* Choose a time likely to be affected by DST in many zones */
    SYSTEMTIME utc_time = {
        .wYear = 2021,
        .wMonth = 6,
        .wDay = 15,
        .wHour = 18,
        .wMinute = 0,
        .wSecond = 0,
        .wMilliseconds = 0
    };

    FILETIME utc_ft;
    TEST_CHECK(SystemTimeToFileTime(&utc_time, &utc_ft));

    FILETIME local_ft;
    TEST_CHECK(FileTimeToLocalFileTime(&utc_ft, &local_ft));

    FILETIME roundtrip;
    TEST_CHECK(LocalFileTimeToFileTime(&local_ft, &roundtrip));
    TEST_CHECK_U64_EQ(filetime_to_u64(&utc_ft), filetime_to_u64(&roundtrip));

    /* Local filetime should convert back to the original system time when interpreted locally */
    SYSTEMTIME local_st = {0};
    TEST_CHECK(FileTimeToSystemTime(&local_ft, &local_st));
    SYSTEMTIME utc_from_roundtrip = {0};
    TEST_CHECK(FileTimeToSystemTime(&roundtrip, &utc_from_roundtrip));
    TEST_CHECK_EQ(utc_time.wYear, utc_from_roundtrip.wYear);
    TEST_CHECK_EQ(utc_time.wMonth, utc_from_roundtrip.wMonth);
    TEST_CHECK_EQ(utc_time.wDay, utc_from_roundtrip.wDay);
    TEST_CHECK_EQ(utc_time.wHour, utc_from_roundtrip.wHour);
    TEST_CHECK_EQ(utc_time.wMinute, utc_from_roundtrip.wMinute);
    TEST_CHECK_EQ(utc_time.wSecond, utc_from_roundtrip.wSecond);
}

int main(void) {
    test_systemtime_roundtrip();
    test_filetime_known_timestamp();
    test_getsystemtimeasfiletime();
    test_gettickcount_progresses();
    test_setfiletime_roundtrip();
    test_local_filetime_conversions();
    return 0;
}

