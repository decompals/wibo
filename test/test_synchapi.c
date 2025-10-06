#include "test_assert.h"
#include <stdlib.h>
#include <windows.h>

typedef struct {
	HANDLE mutex;
	HANDLE acquiredEvent;
	HANDLE releaseEvent;
	HANDLE doneEvent;
} MutexWorkerContext;

static DWORD WINAPI mutex_worker(LPVOID param) {
	MutexWorkerContext *ctx = (MutexWorkerContext *)param;
	DWORD wait = WaitForSingleObject(ctx->mutex, 1000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);
	TEST_CHECK(SetEvent(ctx->acquiredEvent));

	wait = WaitForSingleObject(ctx->releaseEvent, 1000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);
	TEST_CHECK(ReleaseMutex(ctx->mutex));
	TEST_CHECK(SetEvent(ctx->doneEvent));
	return 0;
}

typedef struct {
	HANDLE semaphore;
	HANDLE ackEvent;
	HANDLE doneEvent;
	int iterations;
} SemaphoreWorkerContext;

static DWORD WINAPI semaphore_worker(LPVOID param) {
	SemaphoreWorkerContext *ctx = (SemaphoreWorkerContext *)param;
	for (int i = 0; i < ctx->iterations; ++i) {
		DWORD wait = WaitForSingleObject(ctx->semaphore, 1000);
		TEST_CHECK_EQ(WAIT_OBJECT_0, wait);
		TEST_CHECK(SetEvent(ctx->ackEvent));
	}
	TEST_CHECK(SetEvent(ctx->doneEvent));
	return 0;
}

static void test_mutex_contention(void) {
	HANDLE mutex = CreateMutexA(NULL, FALSE, NULL);
	TEST_CHECK(mutex != NULL);

	HANDLE acquired = CreateEventA(NULL, FALSE, FALSE, NULL);
	HANDLE releaseSignal = CreateEventA(NULL, FALSE, FALSE, NULL);
	HANDLE done = CreateEventA(NULL, FALSE, FALSE, NULL);
	TEST_CHECK(acquired != NULL && releaseSignal != NULL && done != NULL);

	MutexWorkerContext ctx = {
		.mutex = mutex,
		.acquiredEvent = acquired,
		.releaseEvent = releaseSignal,
		.doneEvent = done,
	};

	HANDLE thread = CreateThread(NULL, 0, mutex_worker, &ctx, 0, NULL);
	TEST_CHECK(thread != NULL);

	DWORD wait = WaitForSingleObject(acquired, 1000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	wait = WaitForSingleObject(mutex, 10);
	TEST_CHECK_EQ(WAIT_TIMEOUT, wait);

	TEST_CHECK(SetEvent(releaseSignal));

	wait = WaitForSingleObject(done, 1000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	wait = WaitForSingleObject(mutex, 1000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	wait = WaitForSingleObject(mutex, 0);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	TEST_CHECK(ReleaseMutex(mutex));
	TEST_CHECK(ReleaseMutex(mutex));

	TEST_CHECK(CloseHandle(thread));
	TEST_CHECK(CloseHandle(acquired));
	TEST_CHECK(CloseHandle(releaseSignal));
	TEST_CHECK(CloseHandle(done));
	TEST_CHECK(CloseHandle(mutex));
}

static void test_semaphore_waits(void) {
	HANDLE semaphore = CreateSemaphoreA(NULL, 0, 3, NULL);
	TEST_CHECK(semaphore != NULL);

	DWORD wait = WaitForSingleObject(semaphore, 10);
	TEST_CHECK_EQ(WAIT_TIMEOUT, wait);

	HANDLE ack = CreateEventA(NULL, FALSE, FALSE, NULL);
	HANDLE done = CreateEventA(NULL, FALSE, FALSE, NULL);
	TEST_CHECK(ack != NULL && done != NULL);

	SemaphoreWorkerContext ctx = {
		.semaphore = semaphore,
		.ackEvent = ack,
		.doneEvent = done,
		.iterations = 3,
	};

	HANDLE thread = CreateThread(NULL, 0, semaphore_worker, &ctx, 0, NULL);
	TEST_CHECK(thread != NULL);

	for (int i = 0; i < ctx.iterations; ++i) {
		LONG previous = -1;
		BOOL ok = ReleaseSemaphore(semaphore, 1, &previous);
		TEST_CHECK(ok);
		TEST_CHECK_EQ(0, previous);
		DWORD ackWait = WaitForSingleObject(ack, 1000);
		TEST_CHECK_EQ(WAIT_OBJECT_0, ackWait);
	}

	DWORD doneWait = WaitForSingleObject(done, 1000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, doneWait);

	// lReleaseCount = 0 permitted; no effect
	TEST_CHECK(ReleaseSemaphore(semaphore, 0, NULL));

	HANDLE limited = CreateSemaphoreA(NULL, 1, 1, NULL);
	TEST_CHECK(limited != NULL);
	SetLastError(0);
	TEST_CHECK(!ReleaseSemaphore(limited, 1, NULL));
	TEST_CHECK_EQ(ERROR_TOO_MANY_POSTS, GetLastError());

	TEST_CHECK(CloseHandle(thread));
	TEST_CHECK(CloseHandle(ack));
	TEST_CHECK(CloseHandle(done));
	TEST_CHECK(CloseHandle(semaphore));
	TEST_CHECK(CloseHandle(limited));
}

int main(void) {
	test_mutex_contention();
	test_semaphore_waits();
	return EXIT_SUCCESS;
}
