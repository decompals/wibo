#include "test_assert.h"
#include <windows.h>

typedef struct {
	CRITICAL_SECTION *section;
	HANDLE ready;
	HANDLE release;
	HANDLE done;
} HoldWorkerContext;

static DWORD WINAPI hold_worker(LPVOID param) {
	HoldWorkerContext *ctx = (HoldWorkerContext *)param;
	EnterCriticalSection(ctx->section);
	TEST_CHECK(SetEvent(ctx->ready));

	DWORD wait = WaitForSingleObject(ctx->release, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	LeaveCriticalSection(ctx->section);
	TEST_CHECK(SetEvent(ctx->done));
	return 0;
}

typedef struct {
	CRITICAL_SECTION *section;
	HANDLE entered;
	HANDLE done;
} WaitWorkerContext;

static DWORD WINAPI wait_worker(LPVOID param) {
	WaitWorkerContext *ctx = (WaitWorkerContext *)param;
	EnterCriticalSection(ctx->section);
	TEST_CHECK(SetEvent(ctx->entered));
	LeaveCriticalSection(ctx->section);
	TEST_CHECK(SetEvent(ctx->done));
	return 0;
}

static void close_handle(HANDLE h) {
	if (h) {
		TEST_CHECK(CloseHandle(h));
	}
}

static void test_try_enter_contention(void) {
	CRITICAL_SECTION cs;
	InitializeCriticalSection(&cs);

	HANDLE ready = CreateEventA(NULL, FALSE, FALSE, NULL);
	HANDLE release = CreateEventA(NULL, FALSE, FALSE, NULL);
	HANDLE done = CreateEventA(NULL, FALSE, FALSE, NULL);
	TEST_CHECK(ready && release && done);

	HoldWorkerContext ctx = {
		.section = &cs,
		.ready = ready,
		.release = release,
		.done = done,
	};

	HANDLE thread = CreateThread(NULL, 0, hold_worker, &ctx, 0, NULL);
	TEST_CHECK(thread != NULL);

	DWORD wait = WaitForSingleObject(ready, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	BOOL canEnter = TryEnterCriticalSection(&cs);
	TEST_CHECK_EQ(FALSE, canEnter);

	TEST_CHECK(SetEvent(release));

	wait = WaitForSingleObject(done, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);
	wait = WaitForSingleObject(thread, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	BOOL reacquire = TryEnterCriticalSection(&cs);
	TEST_CHECK(reacquire);
	LeaveCriticalSection(&cs);

	close_handle(thread);
	close_handle(ready);
	close_handle(release);
	close_handle(done);

	DeleteCriticalSection(&cs);
}

static void test_recursive_behavior(void) {
	CRITICAL_SECTION cs;
	InitializeCriticalSection(&cs);

	EnterCriticalSection(&cs);
	EnterCriticalSection(&cs);
	TEST_CHECK(TryEnterCriticalSection(&cs));

	LeaveCriticalSection(&cs);
	TEST_CHECK(TryEnterCriticalSection(&cs));

	LeaveCriticalSection(&cs);
	LeaveCriticalSection(&cs);
	LeaveCriticalSection(&cs);

	TEST_CHECK(TryEnterCriticalSection(&cs));
	LeaveCriticalSection(&cs);

	DeleteCriticalSection(&cs);
}

static void test_wait_contention(void) {
	CRITICAL_SECTION cs;
	InitializeCriticalSection(&cs);

	EnterCriticalSection(&cs);

	HANDLE entered = CreateEventA(NULL, FALSE, FALSE, NULL);
	HANDLE done = CreateEventA(NULL, FALSE, FALSE, NULL);
	TEST_CHECK(entered && done);

	WaitWorkerContext ctx = {
		.section = &cs,
		.entered = entered,
		.done = done,
	};

	HANDLE thread = CreateThread(NULL, 0, wait_worker, &ctx, 0, NULL);
	TEST_CHECK(thread != NULL);

	DWORD wait = WaitForSingleObject(entered, 100);
	TEST_CHECK_EQ(WAIT_TIMEOUT, wait);

	LeaveCriticalSection(&cs);

	wait = WaitForSingleObject(entered, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);
	wait = WaitForSingleObject(done, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);
	wait = WaitForSingleObject(thread, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	TEST_CHECK(TryEnterCriticalSection(&cs));
	LeaveCriticalSection(&cs);

	close_handle(thread);
	close_handle(entered);
	close_handle(done);

	DeleteCriticalSection(&cs);
}

static void test_delete_and_reinit(void) {
	CRITICAL_SECTION cs;
	InitializeCriticalSection(&cs);

	EnterCriticalSection(&cs);
	LeaveCriticalSection(&cs);
	DeleteCriticalSection(&cs);

	BOOL initAgain =
		InitializeCriticalSectionEx(&cs, 4000, RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO);
	TEST_CHECK(initAgain);

	TEST_CHECK(TryEnterCriticalSection(&cs));
	LeaveCriticalSection(&cs);
	DeleteCriticalSection(&cs);
}

int main(void) {
	test_recursive_behavior();
	test_wait_contention();
	test_try_enter_contention();
	test_delete_and_reinit();
	return EXIT_SUCCESS;
}
