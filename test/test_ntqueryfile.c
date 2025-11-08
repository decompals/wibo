#include <string.h>
#include <windows.h>
#include <winternl.h>

#include "test_assert.h"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef STATUS_INVALID_HANDLE
#define STATUS_INVALID_HANDLE ((NTSTATUS)0xC0000008L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif

#ifndef STATUS_OBJECT_TYPE_MISMATCH
#define STATUS_OBJECT_TYPE_MISMATCH ((NTSTATUS)0xC0000024L)
#endif

typedef NTSTATUS(WINAPI *NtQueryInformationFileFn)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
                                                   PVOID FileInformation, ULONG Length,
                                                   FILE_INFORMATION_CLASS FileInformationClass);

static NtQueryInformationFileFn gNtQueryInformationFile;
static char gTempPath[MAX_PATH];
static char gTempFile[MAX_PATH];

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

static void ensure_loaded(void) {
    if (gNtQueryInformationFile) {
        return;
    }
    FARPROC proc = load_ntdll_proc("NtQueryInformationFile");
    TEST_CHECK(sizeof(gNtQueryInformationFile) == sizeof(proc));
    memcpy(&gNtQueryInformationFile, &proc, sizeof(gNtQueryInformationFile));
}

static HANDLE create_temp_file(void) {
    DWORD pathLen = GetTempPathA(sizeof(gTempPath), gTempPath);
    TEST_CHECK(pathLen > 0 && pathLen < sizeof(gTempPath));

    UINT unique = GetTempFileNameA(gTempPath, "NQI", 0, gTempFile);
    TEST_CHECK(unique != 0);

    HANDLE file = CreateFileA(gTempFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    TEST_CHECK(file != INVALID_HANDLE_VALUE);
    return file;
}

static void test_basic_and_standard_information(HANDLE file, size_t bytesWritten) {
    IO_STATUS_BLOCK iosb;
    FILE_BASIC_INFORMATION basic;
    NTSTATUS status =
        gNtQueryInformationFile(file, &iosb, &basic, sizeof(basic), FileBasicInformation);
    TEST_CHECK_EQ(STATUS_SUCCESS, status);
    TEST_CHECK_EQ(sizeof(basic), iosb.Information);
    TEST_CHECK((basic.FileAttributes & FILE_ATTRIBUTE_ARCHIVE) != 0);
    TEST_CHECK(basic.CreationTime.QuadPart != 0);
    TEST_CHECK(basic.LastWriteTime.QuadPart != 0);

    FILE_STANDARD_INFORMATION standardInfo;
    status = gNtQueryInformationFile(file, &iosb, &standardInfo, sizeof(standardInfo),
                                     FileStandardInformation);
    TEST_CHECK_EQ(STATUS_SUCCESS, status);
    TEST_CHECK_EQ(sizeof(standardInfo), iosb.Information);
    TEST_CHECK_EQ((LONGLONG)bytesWritten, standardInfo.EndOfFile.QuadPart);
    TEST_CHECK(standardInfo.AllocationSize.QuadPart >= (LONGLONG)bytesWritten);
    TEST_CHECK_EQ(FALSE, standardInfo.DeletePending);
    TEST_CHECK_EQ(FALSE, standardInfo.Directory);
    TEST_CHECK(standardInfo.NumberOfLinks >= 1);
}

static void test_position_information(HANDLE file, size_t expectedOffset) {
    IO_STATUS_BLOCK iosb;
    FILE_POSITION_INFORMATION positionInfo;
    NTSTATUS status = gNtQueryInformationFile(file, &iosb, &positionInfo, sizeof(positionInfo),
                                              FilePositionInformation);
    TEST_CHECK_EQ(STATUS_SUCCESS, status);
    TEST_CHECK_EQ(sizeof(positionInfo), iosb.Information);
    TEST_CHECK_EQ((LONGLONG)expectedOffset, positionInfo.CurrentByteOffset.QuadPart);
}

static void test_file_name_information(HANDLE file) {
    unsigned char buffer[sizeof(FILE_NAME_INFORMATION) + 512];
    IO_STATUS_BLOCK iosb;
    NTSTATUS status = gNtQueryInformationFile(file, &iosb, buffer, sizeof(buffer),
                                              FileNameInformation);
    TEST_CHECK_EQ(STATUS_SUCCESS, status);
    PFILE_NAME_INFORMATION nameInfo = (PFILE_NAME_INFORMATION)buffer;
    TEST_CHECK(nameInfo->FileNameLength > 0);
    TEST_CHECK_EQ(sizeof(ULONG) + nameInfo->FileNameLength, iosb.Information);

    size_t chars = nameInfo->FileNameLength / sizeof(WCHAR);
    char narrow[512];
    TEST_CHECK(chars < sizeof(narrow));
    for (size_t i = 0; i < chars; ++i) {
        WCHAR ch = nameInfo->FileName[i];
        TEST_CHECK(ch < 0x80);
        narrow[i] = (char)ch;
    }
    narrow[chars] = '\0';

    const char *expected = strchr(gTempFile, ':');
    if (expected) {
        ++expected;
    } else {
        expected = gTempFile;
    }
    TEST_CHECK_STR_EQ(expected, narrow);
}

static void test_invalid_cases(HANDLE file) {
    IO_STATUS_BLOCK iosb;
    FILE_BASIC_INFORMATION basic;
    NTSTATUS status = gNtQueryInformationFile(file, &iosb, &basic, sizeof(basic) - 1,
                                              FileBasicInformation);
    TEST_CHECK_EQ((NTSTATUS)STATUS_INFO_LENGTH_MISMATCH, status);

    status = gNtQueryInformationFile(INVALID_HANDLE_VALUE, &iosb, &basic, sizeof(basic),
                                     FileBasicInformation);
    TEST_CHECK_EQ((NTSTATUS)STATUS_OBJECT_TYPE_MISMATCH, status);
}

int main(void) {
    ensure_loaded();
    TEST_CHECK(gNtQueryInformationFile != NULL);

    HANDLE file = create_temp_file();

    const char *data = "ntqueryfile";
    DWORD written = 0;
    TEST_CHECK(WriteFile(file, data, (DWORD)strlen(data), &written, NULL));

    test_basic_and_standard_information(file, written);
    test_position_information(file, written);

    TEST_CHECK(SetFilePointer(file, 3, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER);
    test_position_information(file, 3);
    test_file_name_information(file);
    test_invalid_cases(file);

    CloseHandle(file);
    DeleteFileA(gTempFile);
    return 0;
}
