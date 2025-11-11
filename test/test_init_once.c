#include "test_assert.h"

#include <minwindef.h>
#include <windows.h>

typedef struct {
	INIT_ONCE *initOnce;
	HANDLE started;
	HANDLE allowComplete;
	HANDLE done;
	LPVOID resultContext;
	BOOL beginOk;
	BOOL beginPending;
} InitWorkerContext;

static DWORD WINAPI init_worker(LPVOID param) {
	InitWorkerContext *ctx = (InitWorkerContext *)param;
	LPVOID context = NULL;
	BOOL pending = FALSE;
	ctx->beginOk = InitOnceBeginInitialize(ctx->initOnce, 0, &pending, &context);
	ctx->beginPending = pending;
	TEST_CHECK(ctx->beginOk);
	TEST_CHECK(pending);
	TEST_CHECK(context == NULL);
	TEST_CHECK(SetEvent(ctx->started));

	DWORD wait = WaitForSingleObject(ctx->allowComplete, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	ctx->resultContext = (LPVOID)0x1234;
	TEST_CHECK(InitOnceComplete(ctx->initOnce, 0, ctx->resultContext));
	TEST_CHECK(SetEvent(ctx->done));
	return 0;
}

typedef struct {
	INIT_ONCE *initOnce;
	HANDLE readyToWait;
	LPVOID contextOut;
	BOOL beginOk;
	BOOL pending;
} WaiterContext;

static DWORD WINAPI init_waiter(LPVOID param) {
	WaiterContext *ctx = (WaiterContext *)param;
	TEST_CHECK(SetEvent(ctx->readyToWait));
	LPVOID context = (LPVOID)0xDEADBEEF;
	BOOL pending = FALSE;
	ctx->beginOk = InitOnceBeginInitialize(ctx->initOnce, 0, &pending, &context);
	ctx->pending = pending;
	ctx->contextOut = context;
	return 0;
}

static void test_basic_init_once(void) {
	INIT_ONCE initOnce = INIT_ONCE_STATIC_INIT;

	HANDLE workerStarted = CreateEventA(NULL, FALSE, FALSE, NULL);
	HANDLE allowComplete = CreateEventA(NULL, FALSE, FALSE, NULL);
	HANDLE workerDone = CreateEventA(NULL, FALSE, FALSE, NULL);
	HANDLE waiterReady = CreateEventA(NULL, FALSE, FALSE, NULL);
	TEST_CHECK(workerStarted && allowComplete && workerDone && waiterReady);

	InitWorkerContext workerCtx = {
		.initOnce = &initOnce,
		.started = workerStarted,
		.allowComplete = allowComplete,
		.done = workerDone,
		.resultContext = NULL,
		.beginOk = FALSE,
		.beginPending = FALSE,
	};
	WaiterContext waiterCtx = {
		.initOnce = &initOnce,
		.readyToWait = waiterReady,
		.contextOut = NULL,
		.beginOk = FALSE,
		.pending = FALSE,
	};

	HANDLE workerThread = CreateThread(NULL, 0, init_worker, &workerCtx, 0, NULL);
	TEST_CHECK(workerThread != NULL);

	DWORD wait = WaitForSingleObject(workerStarted, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	HANDLE waiterThread = CreateThread(NULL, 0, init_waiter, &waiterCtx, 0, NULL);
	TEST_CHECK(waiterThread != NULL);

	wait = WaitForSingleObject(waiterReady, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);
	Sleep(10);

	TEST_CHECK(SetEvent(allowComplete));

	wait = WaitForSingleObject(workerDone, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);
	wait = WaitForSingleObject(workerThread, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);
	wait = WaitForSingleObject(waiterThread, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	TEST_CHECK(workerCtx.beginOk);
	TEST_CHECK(workerCtx.beginPending);
	TEST_CHECK(waiterCtx.beginOk);
	TEST_CHECK(!waiterCtx.pending);
	TEST_CHECK(waiterCtx.contextOut == workerCtx.resultContext);

	BOOL pending = FALSE;
	LPVOID context = NULL;
	TEST_CHECK(InitOnceBeginInitialize(&initOnce, INIT_ONCE_CHECK_ONLY, &pending, &context));
	TEST_CHECK(!pending);
	TEST_CHECK(context == workerCtx.resultContext);

	pending = TRUE;
	context = NULL;
	TEST_CHECK(InitOnceBeginInitialize(&initOnce, 0, &pending, &context));
	TEST_CHECK(!pending);
	TEST_CHECK(context == workerCtx.resultContext);

	TEST_CHECK(CloseHandle(workerThread));
	TEST_CHECK(CloseHandle(waiterThread));
	TEST_CHECK(CloseHandle(workerStarted));
	TEST_CHECK(CloseHandle(allowComplete));
	TEST_CHECK(CloseHandle(workerDone));
	TEST_CHECK(CloseHandle(waiterReady));
}

static void test_init_once_failure(void) {
	INIT_ONCE initOnce = INIT_ONCE_STATIC_INIT;

	BOOL pending = FALSE;
	LPVOID context = NULL;

	TEST_CHECK(InitOnceBeginInitialize(&initOnce, 0, &pending, &context));
	TEST_CHECK(pending);
	TEST_CHECK(context == NULL);
	TEST_CHECK(InitOnceComplete(&initOnce, INIT_ONCE_INIT_FAILED, NULL));

	pending = FALSE;
	context = (LPVOID)0x1;
	TEST_CHECK(InitOnceBeginInitialize(&initOnce, 0, &pending, &context));
	TEST_CHECK(pending);
	TEST_CHECK(context == (LPVOID)0x1);

	LPVOID finalContext = (LPVOID)0x7774;
	TEST_CHECK(InitOnceComplete(&initOnce, 0, finalContext));

	pending = TRUE;
	context = NULL;
	TEST_CHECK(InitOnceBeginInitialize(&initOnce, INIT_ONCE_CHECK_ONLY, &pending, &context));
	TEST_CHECK(!pending);
	TEST_CHECK(context == finalContext);
}

static void test_async_init_once(void) {
	INIT_ONCE initOnce = INIT_ONCE_STATIC_INIT;

	BOOL pending = FALSE;
	LPVOID context = NULL;
	TEST_CHECK(InitOnceBeginInitialize(&initOnce, INIT_ONCE_ASYNC, &pending, &context));
	TEST_CHECK(pending);
	TEST_CHECK(context == NULL);

	SetLastError(0);
	pending = FALSE;
	context = NULL;
	TEST_CHECK(!InitOnceBeginInitialize(&initOnce, 0, &pending, &context));
	TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());

	pending = FALSE;
	context = NULL;
	TEST_CHECK(InitOnceBeginInitialize(&initOnce, INIT_ONCE_ASYNC, &pending, &context));
	TEST_CHECK(pending);

	LPVOID finalContext = (LPVOID)0xABCC;
	TEST_CHECK(InitOnceComplete(&initOnce, INIT_ONCE_ASYNC, finalContext));

	pending = TRUE;
	context = NULL;
	TEST_CHECK(InitOnceBeginInitialize(&initOnce, 0, &pending, &context));
	TEST_CHECK(!pending);
	TEST_CHECK(context == finalContext);
}

int main(void) {
	test_basic_init_once();
	test_init_once_failure();
	test_async_init_once();
	return 0;
}
