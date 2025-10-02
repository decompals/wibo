#include <windows.h>
#include <winternl.h>
#include <wchar.h>
#include <string.h>

#include "test_assert.h"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef STATUS_INVALID_INFO_CLASS
#define STATUS_INVALID_INFO_CLASS ((NTSTATUS)0xC0000003L)
#endif

typedef NTSTATUS(NTAPI *NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

static WCHAR wide_to_upper(WCHAR ch) {
    if (ch >= L'a' && ch <= L'z') {
        return ch - (WCHAR)32;
    }
    return ch;
}

static int wide_cmp_case_insensitive(const WCHAR *lhs, const WCHAR *rhs) {
    while (*lhs && *rhs) {
        WCHAR a = wide_to_upper(*lhs);
        WCHAR b = wide_to_upper(*rhs);
        if (a != b) {
            break;
        }
        ++lhs;
        ++rhs;
    }
    return (int)wide_to_upper(*lhs) - (int)wide_to_upper(*rhs);
}

static const WCHAR *skip_nt_path_prefix(const WCHAR *path) {
    if (!path) {
        return path;
    }
    if (path[0] == L'\\' && path[1] == L'?' && path[2] == L'?' && path[3] == L'\\') {
        return path + 4;
    }
    return path;
}

static NtQueryInformationProcess_t load_ntquery(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        ntdll = LoadLibraryW(L"ntdll.dll");
    }
    TEST_CHECK(ntdll != NULL);
    FARPROC proc = GetProcAddress(ntdll, "NtQueryInformationProcess");
    TEST_CHECK(proc != NULL);
    NtQueryInformationProcess_t fn = NULL;
    TEST_CHECK(sizeof(fn) == sizeof(proc));
    memcpy(&fn, &proc, sizeof(fn));
    return fn;
}

static void test_basic_information(NtQueryInformationProcess_t fn) {
    PROCESS_BASIC_INFORMATION info;
    ULONG returnLength = 0;
    NTSTATUS status = fn(GetCurrentProcess(), ProcessBasicInformation, &info, sizeof(info), &returnLength);
    TEST_CHECK_EQ((NTSTATUS)STATUS_SUCCESS, status);
    TEST_CHECK(returnLength >= sizeof(info));
    TEST_CHECK_EQ((ULONG_PTR)GetCurrentProcessId(), info.UniqueProcessId);
    TEST_CHECK(info.PebBaseAddress != NULL);
    TEST_CHECK_EQ(STILL_ACTIVE, (DWORD)info.ExitStatus);
}

static void test_wow64_information(NtQueryInformationProcess_t fn) {
    ULONG_PTR wow64 = (ULONG_PTR)0xDEADBEEF;
    ULONG returnLength = 0;
    NTSTATUS status = fn(GetCurrentProcess(), ProcessWow64Information, &wow64, sizeof(wow64), &returnLength);
    TEST_CHECK_EQ((NTSTATUS)STATUS_SUCCESS, status);
    TEST_CHECK_EQ((ULONG)sizeof(ULONG_PTR), returnLength);

    BOOL isWow64 = FALSE;
    if (IsWow64Process(GetCurrentProcess(), &isWow64) && isWow64) {
        TEST_CHECK(wow64 != 0);
    } else {
        TEST_CHECK_EQ((ULONG_PTR)0, wow64);
    }
}

static void test_image_file_name(NtQueryInformationProcess_t fn) {
    unsigned char buffer[sizeof(UNICODE_STRING) + 1024];
    ULONG returnLength = 0;
    NTSTATUS status = fn(GetCurrentProcess(), ProcessImageFileName, buffer, sizeof(buffer), &returnLength);
    TEST_CHECK_EQ((NTSTATUS)STATUS_SUCCESS, status);
    TEST_CHECK(returnLength > sizeof(UNICODE_STRING));

    UNICODE_STRING *u = (UNICODE_STRING *)buffer;
    TEST_CHECK(u->Buffer != NULL);
    TEST_CHECK(u->Length % sizeof(WCHAR) == 0);

    int charCount = (int)(u->Length / sizeof(WCHAR));
    WCHAR from_ntquery[512];
    TEST_CHECK(charCount < (int)(sizeof(from_ntquery) / sizeof(from_ntquery[0])));
    memcpy(from_ntquery, u->Buffer, u->Length);
    from_ntquery[charCount] = L'\0';

    WCHAR expected[512];
    DWORD len = GetModuleFileNameW(NULL, expected, (DWORD)(sizeof(expected) / sizeof(expected[0])));
    TEST_CHECK(len > 0);
    const WCHAR *normalized_expected = skip_nt_path_prefix(expected);
    const WCHAR *normalized_actual = skip_nt_path_prefix(from_ntquery);
    TEST_CHECK_MSG(wide_cmp_case_insensitive(normalized_expected, normalized_actual) == 0,
                   "expected %ls, got %ls", normalized_expected, normalized_actual);
}

static void test_invalid_lengths(NtQueryInformationProcess_t fn) {
    PROCESS_BASIC_INFORMATION info;
    ULONG returnLength = 0;
    NTSTATUS status = fn(GetCurrentProcess(), ProcessBasicInformation, &info, sizeof(info) - 1, &returnLength);
    TEST_CHECK_EQ((NTSTATUS)STATUS_INFO_LENGTH_MISMATCH, status);
    TEST_CHECK_EQ((ULONG)sizeof(PROCESS_BASIC_INFORMATION), returnLength);

    ULONG_PTR wow64 = 0;
    status = fn(GetCurrentProcess(), ProcessWow64Information, &wow64, sizeof(wow64) - 1, &returnLength);
    TEST_CHECK_EQ((NTSTATUS)STATUS_INFO_LENGTH_MISMATCH, status);
}

static void test_invalid_class(NtQueryInformationProcess_t fn) {
    ULONG dummy = 0;
    NTSTATUS status = fn(GetCurrentProcess(), (PROCESSINFOCLASS)1234, &dummy, sizeof(dummy), NULL);
    TEST_CHECK_EQ((NTSTATUS)STATUS_INVALID_INFO_CLASS, status);
}

int main(void) {
    NtQueryInformationProcess_t fn = load_ntquery();
    test_basic_information(fn);
    test_wow64_information(fn);
    test_image_file_name(fn);
    test_invalid_lengths(fn);
    test_invalid_class(fn);
    return 0;
}
