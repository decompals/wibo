#define _WIN32_WINNT 0x0600

#include "test_assert.h"
#include <stdlib.h>
#include <windows.h>

#ifndef FLS_OUT_OF_INDEXES
#define FLS_OUT_OF_INDEXES ((DWORD)0xffffffff)
#endif

typedef struct {
	DWORD index;
	HANDLE readyEvent;
	HANDLE continueEvent;
	int threadValue;
	int reuseValue;
} FlsThreadContext;

static DWORD WINAPI fls_thread_proc(LPVOID param) {
	FlsThreadContext *ctx = (FlsThreadContext *)param;
	TEST_CHECK(ctx != NULL);

	SetLastError(ERROR_GEN_FAILURE);
	TEST_CHECK(FlsGetValue(ctx->index) == NULL);
	TEST_CHECK_EQ(ERROR_SUCCESS, GetLastError());

	TEST_CHECK(FlsSetValue(ctx->index, &ctx->threadValue));
	TEST_CHECK(FlsGetValue(ctx->index) == &ctx->threadValue);
	TEST_CHECK(SetEvent(ctx->readyEvent));

	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(ctx->continueEvent, 1000));

	SetLastError(ERROR_GEN_FAILURE);
	TEST_CHECK(FlsGetValue(ctx->index) == NULL);
	TEST_CHECK_EQ(ERROR_SUCCESS, GetLastError());

	TEST_CHECK(FlsSetValue(ctx->index, &ctx->reuseValue));
	TEST_CHECK(FlsGetValue(ctx->index) == &ctx->reuseValue);

	return 0;
}

int main(void) {
	DWORD index = FlsAlloc(NULL);
	TEST_CHECK(index != FLS_OUT_OF_INDEXES);

	SetLastError(ERROR_GEN_FAILURE);
	TEST_CHECK(FlsGetValue(index) == NULL);
	TEST_CHECK_EQ(ERROR_SUCCESS, GetLastError());

	int mainValue = 0x1234;
	TEST_CHECK(FlsSetValue(index, &mainValue));
	TEST_CHECK(FlsGetValue(index) == &mainValue);

	FlsThreadContext ctx = {0};
	ctx.index = index;
	ctx.threadValue = 0x5678;
	ctx.reuseValue = 0x9abc;
	ctx.readyEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
	ctx.continueEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
	TEST_CHECK(ctx.readyEvent != NULL);
	TEST_CHECK(ctx.continueEvent != NULL);

	HANDLE thread = CreateThread(NULL, 0, fls_thread_proc, &ctx, 0, NULL);
	TEST_CHECK(thread != NULL);

	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(ctx.readyEvent, 1000));
	TEST_CHECK(FlsGetValue(index) == &mainValue);

	TEST_CHECK(FlsFree(index));
	TEST_CHECK(FlsGetValue(index) == NULL);

	DWORD reusedIndex = FlsAlloc(NULL);
	TEST_CHECK_EQ(index, reusedIndex);

	SetLastError(ERROR_GEN_FAILURE);
	TEST_CHECK(FlsGetValue(reusedIndex) == NULL);
	TEST_CHECK_EQ(ERROR_SUCCESS, GetLastError());

	TEST_CHECK(SetEvent(ctx.continueEvent));
	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(thread, 1000));

	TEST_CHECK(CloseHandle(thread));
	TEST_CHECK(CloseHandle(ctx.readyEvent));
	TEST_CHECK(CloseHandle(ctx.continueEvent));
	TEST_CHECK(FlsFree(reusedIndex));

	return EXIT_SUCCESS;
}
