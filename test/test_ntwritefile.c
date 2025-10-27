#include "test_assert.h"

#define WIN32_LEAN_AND_MEAN
#include <string.h>
#include <windows.h>
#include <winternl.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

static const char *kTempFileName = "ntwritefile_fixture.tmp";

typedef NTSTATUS(NTAPI *NtWriteFile_t)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
									   PLARGE_INTEGER, PULONG);

static NtWriteFile_t load_ntwritefile(void) {
	HMODULE mod = GetModuleHandleW(L"ntdll.dll");
	if (!mod) {
		mod = LoadLibraryW(L"ntdll.dll");
	}
	TEST_CHECK(mod != NULL);
	FARPROC proc = GetProcAddress(mod, "NtWriteFile");
	TEST_CHECK(proc != NULL);
	NtWriteFile_t fn = NULL;
	TEST_CHECK(sizeof(fn) == sizeof(proc));
	memcpy(&fn, &proc, sizeof(fn));
	return fn;
}

static void read_back(HANDLE file, char *buffer, DWORD expectedLength) {
	TEST_CHECK(SetFilePointer(file, 0, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER);
	DWORD read = 0;
	memset(buffer, 0, expectedLength + 1);
	TEST_CHECK(ReadFile(file, buffer, expectedLength, &read, NULL));
	TEST_CHECK_EQ(expectedLength, read);
}

int main(void) {
	NtWriteFile_t fn = load_ntwritefile();

	DeleteFileA(kTempFileName);
	HANDLE file =
		CreateFileA(kTempFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	TEST_CHECK(file != INVALID_HANDLE_VALUE);

	HANDLE event = CreateEventA(NULL, TRUE, TRUE, NULL);
	TEST_CHECK(event != NULL);

	IO_STATUS_BLOCK iosb;
	memset(&iosb, 0, sizeof(iosb));

	char payload[] = "hello";
	SetLastError(ERROR_GEN_FAILURE);
	DWORD before = GetLastError();
	NTSTATUS status = fn(file, event, NULL, NULL, &iosb, payload, (ULONG)(sizeof(payload) - 1), NULL, NULL);
	TEST_CHECK_EQ((NTSTATUS)STATUS_SUCCESS, status);
	TEST_CHECK_EQ(status, iosb.Status);
	TEST_CHECK_EQ((ULONG_PTR)(sizeof(payload) - 1), iosb.Information);
	TEST_CHECK_EQ(before, GetLastError());
	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(event, 0));

	char buffer[16];
	read_back(file, buffer, 5);
	TEST_CHECK(memcmp(buffer, "hello", 5) == 0);
	TEST_CHECK(ResetEvent(event));

	LARGE_INTEGER useCurrent;
	useCurrent.QuadPart = -2; // FILE_USE_FILE_POINTER_POSITION
	TEST_CHECK(SetFilePointer(file, 1, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER);
	IO_STATUS_BLOCK overwriteIosb;
	memset(&overwriteIosb, 0, sizeof(overwriteIosb));
	char middle[] = "abc";
	SetLastError(ERROR_GEN_FAILURE);
	before = GetLastError();
	status = fn(file, event, NULL, NULL, &overwriteIosb, middle, (ULONG)(sizeof(middle) - 1), &useCurrent, NULL);
	TEST_CHECK_EQ((NTSTATUS)STATUS_SUCCESS, status);
	TEST_CHECK_EQ(status, overwriteIosb.Status);
	TEST_CHECK_EQ((ULONG_PTR)(sizeof(middle) - 1), overwriteIosb.Information);
	TEST_CHECK_EQ(before, GetLastError());
	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(event, 0));

	read_back(file, buffer, 5);
	TEST_CHECK(memcmp(buffer, "habco", 5) == 0);
	TEST_CHECK(ResetEvent(event));

	LARGE_INTEGER appendPos;
	appendPos.QuadPart = -1; // FILE_WRITE_TO_END_OF_FILE
	IO_STATUS_BLOCK appendIosb;
	memset(&appendIosb, 0, sizeof(appendIosb));
	char tail[] = "!";
	SetLastError(ERROR_GEN_FAILURE);
	before = GetLastError();
	status = fn(file, event, NULL, NULL, &appendIosb, tail, (ULONG)(sizeof(tail) - 1), &appendPos, NULL);
	TEST_CHECK_EQ((NTSTATUS)STATUS_SUCCESS, status);
	TEST_CHECK_EQ(status, appendIosb.Status);
	TEST_CHECK_EQ((ULONG_PTR)(sizeof(tail) - 1), appendIosb.Information);
	TEST_CHECK_EQ(before, GetLastError());
	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(event, 0));

	read_back(file, buffer, 6);
	TEST_CHECK(memcmp(buffer, "habco!", 6) == 0);

	TEST_CHECK(CloseHandle(event));
	TEST_CHECK(CloseHandle(file));
	TEST_CHECK(DeleteFileA(kTempFileName));
	return 0;
}
