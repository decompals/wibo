#include <windows.h>

#include "test_assert.h"

static void normalize_uppercase(char *dst, const char *src, size_t size) {
    size_t i;
    for (i = 0; i + 1 < size && src[i]; ++i) {
        unsigned char ch = (unsigned char)src[i];
        if (ch >= 'a' && ch <= 'z') {
            ch = (unsigned char)(ch - ('a' - 'A'));
        }
        dst[i] = (char)ch;
    }
    dst[i] = '\0';
}

static void expect_directory(const char *expected, const char *actual) {
    char expectedUpper[MAX_PATH];
    char actualUpper[MAX_PATH];
    normalize_uppercase(expectedUpper, expected, sizeof(expectedUpper));
    normalize_uppercase(actualUpper, actual, sizeof(actualUpper));
    TEST_CHECK_STR_EQ(expectedUpper, actualUpper);
}

static void test_ascii(void) {
    char buffer[MAX_PATH];
    UINT written = GetSystemDirectoryA(buffer, sizeof(buffer));
    TEST_CHECK(written > 0);
    TEST_CHECK(written < sizeof(buffer));
    expect_directory("C:\\Windows\\System32", buffer);

    /* Request length only */
    written = GetSystemDirectoryA(buffer, 0);
    TEST_CHECK_EQ((UINT)20, written);

    SetLastError(0xdeadbeef);
    written = GetSystemWow64DirectoryA(buffer, sizeof(buffer));
    if (written == 0) {
        TEST_CHECK_EQ(ERROR_CALL_NOT_IMPLEMENTED, GetLastError());
    } else {
        expect_directory("C:\\Windows\\SysWOW64", buffer);
    }

    SetLastError(0xdeadbeef);
    written = GetSystemWow64DirectoryA(buffer, 0);
    if (written == 0) {
        TEST_CHECK_EQ(ERROR_CALL_NOT_IMPLEMENTED, GetLastError());
    } else {
        TEST_CHECK_EQ((UINT)20, written);
    }
}

static void test_unicode(void) {
    WCHAR buffer[MAX_PATH];
    UINT written = GetSystemDirectoryW(buffer, MAX_PATH);
    TEST_CHECK(written > 0);
    TEST_CHECK(written < MAX_PATH);

    char narrow[MAX_PATH];
    WideCharToMultiByte(CP_UTF8, 0, buffer, -1, narrow, sizeof(narrow), NULL, NULL);
    expect_directory("C:\\Windows\\System32", narrow);

    /* Insufficient buffer */
    WCHAR tiny[8];
    written = GetSystemDirectoryW(tiny, 4);
    TEST_CHECK_EQ((UINT)20, written);

    SetLastError(0xdeadbeef);
    written = GetSystemWow64DirectoryW(buffer, MAX_PATH);
    if (written == 0) {
        TEST_CHECK_EQ(ERROR_CALL_NOT_IMPLEMENTED, GetLastError());
    } else {
        char narrow[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, buffer, -1, narrow, sizeof(narrow), NULL, NULL);
        expect_directory("C:\\Windows\\SysWOW64", narrow);
    }

    SetLastError(0xdeadbeef);
    written = GetSystemWow64DirectoryW(tiny, 4);
    if (written == 0) {
        TEST_CHECK_EQ(ERROR_CALL_NOT_IMPLEMENTED, GetLastError());
    } else {
        TEST_CHECK_EQ((UINT)20, written);
    }
}

int main(void) {
    test_ascii();
    test_unicode();
    return 0;
}
