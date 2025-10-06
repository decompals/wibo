#include "test_assert.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <string.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_END_OF_FILE
#define STATUS_END_OF_FILE ((NTSTATUS)0xC0000011L)
#endif

static const char *kTempFileName = "ntreadfile_fixture.tmp";

typedef NTSTATUS(NTAPI *NtReadFile_t)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
                                      PLARGE_INTEGER, PULONG);

static NtReadFile_t load_ntreadfile(void) {
    HMODULE mod = GetModuleHandleW(L"ntdll.dll");
    if (!mod) {
        mod = LoadLibraryW(L"ntdll.dll");
    }
    TEST_CHECK(mod != NULL);
    FARPROC proc = GetProcAddress(mod, "NtReadFile");
    TEST_CHECK(proc != NULL);
    NtReadFile_t fn = NULL;
    TEST_CHECK(sizeof(fn) == sizeof(proc));
    memcpy(&fn, &proc, sizeof(fn));
    return fn;
}

static void write_fixture(HANDLE file, const char *data, DWORD length) {
    DWORD written = 0;
    TEST_CHECK(WriteFile(file, data, length, &written, NULL));
    TEST_CHECK_EQ(length, written);
    TEST_CHECK(SetFilePointer(file, 0, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER);
}

int main(void) {
    NtReadFile_t fn = load_ntreadfile();

    DeleteFileA(kTempFileName);
    HANDLE file = CreateFileA(kTempFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    TEST_CHECK(file != INVALID_HANDLE_VALUE);

    const char payload[] = "hello";
    write_fixture(file, payload, (DWORD)(sizeof(payload) - 1));

    HANDLE event = CreateEventA(NULL, TRUE, TRUE, NULL);
    TEST_CHECK(event != NULL);

    IO_STATUS_BLOCK iosb;
    memset(&iosb, 0, sizeof(iosb));
    char buffer[6];
    memset(buffer, 0, sizeof(buffer));
    SetLastError(ERROR_GEN_FAILURE);
    DWORD before = GetLastError();
    NTSTATUS status = fn(file, event, NULL, NULL, &iosb, buffer, 5, NULL, NULL);
    TEST_CHECK_EQ((NTSTATUS)STATUS_SUCCESS, status);
    TEST_CHECK_EQ(5u, (unsigned int)iosb.Information);
    TEST_CHECK(memcmp(buffer, payload, 5) == 0);
    TEST_CHECK_EQ(before, GetLastError());
    TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(event, 0));
    TEST_CHECK(ResetEvent(event));

    LARGE_INTEGER useCurrent;
    useCurrent.QuadPart = -2;
    IO_STATUS_BLOCK eofIosb;
    memset(&eofIosb, 0, sizeof(eofIosb));
    memset(buffer, 0, sizeof(buffer));
    SetLastError(ERROR_GEN_FAILURE);
    before = GetLastError();
    status = fn(file, event, NULL, NULL, &eofIosb, buffer, sizeof(buffer), &useCurrent, NULL);
    TEST_CHECK_EQ((NTSTATUS)STATUS_END_OF_FILE, status);
    TEST_CHECK_EQ(0u, (unsigned int)eofIosb.Information);
    TEST_CHECK_EQ(before, GetLastError());
    TEST_CHECK(buffer[0] == 0);
    TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(event, 0));

    TEST_CHECK(CloseHandle(event));
    TEST_CHECK(CloseHandle(file));
    TEST_CHECK(DeleteFileA(kTempFileName));
    return 0;
}
