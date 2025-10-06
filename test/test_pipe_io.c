#include "test_assert.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

#include <string.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_PIPE_BROKEN
#define STATUS_PIPE_BROKEN ((NTSTATUS)0xC000014BL)
#endif

typedef NTSTATUS(NTAPI *NtReadFile_t)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
                                      PLARGE_INTEGER, PULONG);

static NtReadFile_t load_ntreadfile(void) {
    HMODULE mod = GetModuleHandleW(L"ntdll.dll");
    if (!mod) {
        TEST_CHECK_EQ(ERROR_MOD_NOT_FOUND, GetLastError());
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

static void write_bytes(HANDLE handle, const char *data, size_t length) {
    DWORD written = 0;
    TEST_CHECK(WriteFile(handle, data, (DWORD)length, &written, NULL));
    TEST_CHECK_EQ((DWORD)length, written);
}

int main(void) {
    NtReadFile_t fn = load_ntreadfile();

    HANDLE readPipe = NULL;
    HANDLE writePipe = NULL;
    TEST_CHECK(CreatePipe(&readPipe, &writePipe, NULL, 0));

    const char msgReadFile[] = "pipe-read";
    write_bytes(writePipe, msgReadFile, strlen(msgReadFile));

    char buffer[64];
    memset(buffer, 0, sizeof(buffer));
    DWORD bytesRead = 0;
    TEST_CHECK(ReadFile(readPipe, buffer, sizeof(buffer), &bytesRead, NULL));
    TEST_CHECK_EQ((DWORD)strlen(msgReadFile), bytesRead);
    TEST_CHECK(memcmp(buffer, msgReadFile, bytesRead) == 0);

    const char msgNtRead[] = "ntread";
    write_bytes(writePipe, msgNtRead, strlen(msgNtRead));

    HANDLE event = CreateEventA(NULL, TRUE, FALSE, NULL);
    TEST_CHECK(event != NULL);

    IO_STATUS_BLOCK iosb;
    memset(&iosb, 0, sizeof(iosb));
    memset(buffer, 0, sizeof(buffer));
    NTSTATUS status = fn(readPipe, event, NULL, NULL, &iosb, buffer, sizeof(buffer), NULL, NULL);
    TEST_CHECK_EQ((NTSTATUS)STATUS_SUCCESS, status);
    TEST_CHECK_EQ((ULONG_PTR)strlen(msgNtRead), iosb.Information);
    TEST_CHECK(memcmp(buffer, msgNtRead, iosb.Information) == 0);
    TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(event, 0));

    TEST_CHECK(CloseHandle(writePipe));
    writePipe = NULL;

    bytesRead = 123;
    SetLastError(ERROR_GEN_FAILURE);
    TEST_CHECK(!ReadFile(readPipe, buffer, sizeof(buffer), &bytesRead, NULL));
    TEST_CHECK_EQ(0u, (unsigned int)bytesRead);
    TEST_CHECK_EQ(ERROR_BROKEN_PIPE, GetLastError());
    TEST_CHECK(ResetEvent(event));

    memset(&iosb, 0, sizeof(iosb));
    status = fn(readPipe, event, NULL, NULL, &iosb, buffer, sizeof(buffer), NULL, NULL);
    TEST_CHECK_EQ((NTSTATUS)STATUS_PIPE_BROKEN, status);
    TEST_CHECK_EQ(0u, (unsigned int)iosb.Information);
    TEST_CHECK_EQ(WAIT_TIMEOUT, WaitForSingleObject(event, 0));

    TEST_CHECK(CloseHandle(event));
    TEST_CHECK(CloseHandle(readPipe));
    if (writePipe) {
        TEST_CHECK(CloseHandle(writePipe));
    }
    return 0;
}
