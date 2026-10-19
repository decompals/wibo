#include <windows.h>

#include "test_assert.h"

typedef DWORD(WINAPI *GetDwordFn)(void);
typedef void(WINAPI *SetLastErrorFn)(DWORD);
typedef BOOL(WINAPI *IsDBCSLeadByteFn)(BYTE);

typedef struct {
	DWORD apiThreadId;
	DWORD tebThreadId;
	DWORD lastError;
	DWORD tebLastError;
	GetDwordFn fastGetLastError;
	SetLastErrorFn fastSetLastError;
} WorkerResult;

static DWORD teb_thread_id(void) {
	DWORD threadId;
	__asm__ __volatile__("movl %%fs:0x24, %0" : "=r"(threadId));
	return threadId;
}

static DWORD teb_last_error(void) {
	DWORD lastError;
	__asm__ __volatile__("movl %%fs:0x34, %0" : "=r"(lastError));
	return lastError;
}

static FARPROC require_proc(HMODULE kernel32, const char *name) {
	FARPROC proc = GetProcAddress(kernel32, name);
	TEST_CHECK_MSG(proc != NULL, "GetProcAddress(%s) failed: %lu", name, (unsigned long)GetLastError());
	return proc;
}

static DWORD WINAPI read_worker_thread_id(LPVOID opaque) {
	WorkerResult *result = (WorkerResult *)opaque;
	result->apiThreadId = GetCurrentThreadId();
	result->tebThreadId = teb_thread_id();
	result->fastSetLastError(0xABCDEF01);
	result->lastError = result->fastGetLastError();
	result->tebLastError = teb_last_error();
	return 0;
}

static BOOL expected_dbcs_lead_byte(UINT codePage, BYTE value) {
	if (codePage == 932) {
		return (value >= 0x81 && value <= 0x9F) || (value >= 0xE0 && value <= 0xFC);
	}
	if (codePage == 936 || codePage == 949 || codePage == 950 || codePage == 1361) {
		return value >= 0x81 && value <= 0xFE;
	}
	return FALSE;
}

int main(void) {
	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
	TEST_CHECK(kernel32 != NULL);

	GetDwordFn fastGetLastError = (GetDwordFn)require_proc(kernel32, "GetLastError");
	SetLastErrorFn fastSetLastError = (SetLastErrorFn)require_proc(kernel32, "SetLastError");
	GetDwordFn fastGetCurrentThreadId = (GetDwordFn)require_proc(kernel32, "GetCurrentThreadId");
	IsDBCSLeadByteFn fastIsDBCSLeadByte = (IsDBCSLeadByteFn)require_proc(kernel32, "IsDBCSLeadByte");
	GetDwordFn fastGetTickCount = (GetDwordFn)require_proc(kernel32, "GetTickCount");

	TEST_CHECK_EQ((ULONG_PTR)fastGetTickCount, (ULONG_PTR)require_proc(kernel32, "GetTickCount"));
	UINT acp = GetACP();
	if (acp == 28591) {
		TEST_CHECK_EQ((ULONG_PTR)fastGetLastError, (ULONG_PTR)(GetDwordFn)GetLastError);
		TEST_CHECK_EQ((ULONG_PTR)fastSetLastError, (ULONG_PTR)(SetLastErrorFn)SetLastError);
		TEST_CHECK_EQ((ULONG_PTR)fastGetCurrentThreadId, (ULONG_PTR)(GetDwordFn)GetCurrentThreadId);
		TEST_CHECK_EQ((ULONG_PTR)fastIsDBCSLeadByte, (ULONG_PTR)(IsDBCSLeadByteFn)IsDBCSLeadByte);
		TEST_CHECK_EQ((ULONG_PTR)fastGetTickCount, (ULONG_PTR)(GetDwordFn)GetTickCount);
	}

	SetLastError(0x12345678);
	TEST_CHECK_EQ(0x12345678, fastGetLastError());
	fastSetLastError(0x87654321);
	TEST_CHECK_EQ(0x87654321, GetLastError());
	TEST_CHECK_EQ(0x87654321, teb_last_error());
	TEST_CHECK(!CloseHandle(INVALID_HANDLE_VALUE));
	TEST_CHECK_EQ(ERROR_INVALID_HANDLE, fastGetLastError());

	DWORD mainThreadId = GetCurrentThreadId();
	TEST_CHECK(mainThreadId != 0);
	TEST_CHECK_EQ(mainThreadId, fastGetCurrentThreadId());
	TEST_CHECK_EQ(mainThreadId, teb_thread_id());

	WorkerResult worker = {0};
	worker.fastGetLastError = fastGetLastError;
	worker.fastSetLastError = fastSetLastError;
	SetLastError(0x24681357);
	HANDLE thread = CreateThread(NULL, 0, read_worker_thread_id, &worker, 0, NULL);
	TEST_CHECK(thread != NULL);
	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(thread, 1000));
	TEST_CHECK(CloseHandle(thread));
	TEST_CHECK(worker.apiThreadId != 0);
	TEST_CHECK(worker.apiThreadId != mainThreadId);
	TEST_CHECK_EQ(worker.apiThreadId, worker.tebThreadId);
	TEST_CHECK_EQ(0xABCDEF01, worker.lastError);
	TEST_CHECK_EQ(0xABCDEF01, worker.tebLastError);
	TEST_CHECK_EQ(0x24681357, GetLastError());

	for (UINT value = 0; value <= 0xFF; ++value) {
		BOOL expected = expected_dbcs_lead_byte(acp, (BYTE)value);
		TEST_CHECK_EQ(expected, IsDBCSLeadByte((BYTE)value));
		SetLastError(0x13572468);
		TEST_CHECK_EQ(expected, fastIsDBCSLeadByte((BYTE)value));
		TEST_CHECK_EQ(0x13572468, GetLastError());
	}

	DWORD tickStart = GetTickCount();
	DWORD previousTick = tickStart;
	DWORD directTickDelta = 0;
	DWORD fastTickDelta = 0;
	for (unsigned int attempt = 0; attempt < 200; ++attempt) {
		Sleep(5);
		DWORD directTick = GetTickCount();
		DWORD fastTick = fastGetTickCount();
		TEST_CHECK((DWORD)(directTick - previousTick) < 0x80000000);
		TEST_CHECK((DWORD)(fastTick - directTick) < 0x80000000);
		previousTick = fastTick;
		directTickDelta = directTick - tickStart;
		fastTickDelta = fastTick - tickStart;
		if (directTickDelta != 0 && fastTickDelta != 0) {
			break;
		}
	}
	TEST_CHECK_MSG(directTickDelta != 0, "direct GetTickCount did not advance");
	TEST_CHECK_MSG(fastTickDelta != 0, "GetProcAddress GetTickCount did not advance");
	TEST_CHECK_MSG(directTickDelta <= 5000, "direct GetTickCount diff too large: %lu", (unsigned long)directTickDelta);
	TEST_CHECK_MSG(fastTickDelta <= 5000, "GetProcAddress GetTickCount diff too large: %lu",
				   (unsigned long)fastTickDelta);

	return 0;
}
