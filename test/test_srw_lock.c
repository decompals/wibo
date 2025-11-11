#include "test_assert.h"
#include <windows.h>

typedef struct {
	SRWLOCK *lock;
	HANDLE acquired;
	HANDLE release;
	HANDLE done;
} SharedHoldContext;

static DWORD WINAPI shared_hold_worker(LPVOID param) {
	SharedHoldContext *ctx = (SharedHoldContext *)param;
	AcquireSRWLockShared(ctx->lock);
	TEST_CHECK(SetEvent(ctx->acquired));

	DWORD wait = WaitForSingleObject(ctx->release, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	ReleaseSRWLockShared(ctx->lock);
	TEST_CHECK(SetEvent(ctx->done));
	return 0;
}

typedef struct {
	SRWLOCK *lock;
	HANDLE acquired;
	HANDLE done;
} SharedAcquireContext;

static DWORD WINAPI shared_acquire_worker(LPVOID param) {
	SharedAcquireContext *ctx = (SharedAcquireContext *)param;
	AcquireSRWLockShared(ctx->lock);
	TEST_CHECK(SetEvent(ctx->acquired));
	ReleaseSRWLockShared(ctx->lock);
	TEST_CHECK(SetEvent(ctx->done));
	return 0;
}

typedef struct {
	SRWLOCK *lock;
	HANDLE acquired;
	HANDLE release;
	HANDLE done;
} ExclusiveHoldContext;

static DWORD WINAPI exclusive_hold_worker(LPVOID param) {
	ExclusiveHoldContext *ctx = (ExclusiveHoldContext *)param;
	AcquireSRWLockExclusive(ctx->lock);
	TEST_CHECK(SetEvent(ctx->acquired));

	DWORD wait = WaitForSingleObject(ctx->release, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	ReleaseSRWLockExclusive(ctx->lock);
	TEST_CHECK(SetEvent(ctx->done));
	return 0;
}

static void close_pair(HANDLE a, HANDLE b) {
	if (a) {
		TEST_CHECK(CloseHandle(a));
	}
	if (b) {
		TEST_CHECK(CloseHandle(b));
	}
}

static void test_shared_readers(void) {
	SRWLOCK lock = SRWLOCK_INIT;

	HANDLE ready1 = CreateEventA(NULL, FALSE, FALSE, NULL);
	HANDLE release1 = CreateEventA(NULL, FALSE, FALSE, NULL);
	HANDLE done1 = CreateEventA(NULL, FALSE, FALSE, NULL);
	HANDLE ready2 = CreateEventA(NULL, FALSE, FALSE, NULL);
	HANDLE release2 = CreateEventA(NULL, FALSE, FALSE, NULL);
	HANDLE done2 = CreateEventA(NULL, FALSE, FALSE, NULL);
	TEST_CHECK(ready1 && release1 && done1 && ready2 && release2 && done2);

	SharedHoldContext ctx1 = {&lock, ready1, release1, done1};
	SharedHoldContext ctx2 = {&lock, ready2, release2, done2};

	HANDLE t1 = CreateThread(NULL, 0, shared_hold_worker, &ctx1, 0, NULL);
	HANDLE t2 = CreateThread(NULL, 0, shared_hold_worker, &ctx2, 0, NULL);
	TEST_CHECK(t1 && t2);

	DWORD wait = WaitForSingleObject(ready1, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);
	wait = WaitForSingleObject(ready2, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	// Main thread should also be able to take a shared lock while others hold it.
	AcquireSRWLockShared(&lock);
	ReleaseSRWLockShared(&lock);

	TEST_CHECK(SetEvent(release1));
	TEST_CHECK(SetEvent(release2));

	wait = WaitForSingleObject(done1, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);
	wait = WaitForSingleObject(done2, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	wait = WaitForSingleObject(t1, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);
	wait = WaitForSingleObject(t2, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	TEST_CHECK(CloseHandle(t1));
	TEST_CHECK(CloseHandle(t2));
	close_pair(ready1, release1);
	close_pair(done1, ready2);
	close_pair(release2, done2);
}

static void test_exclusive_blocks_shared(void) {
	SRWLOCK lock = SRWLOCK_INIT;
	AcquireSRWLockExclusive(&lock);

	HANDLE acquired = CreateEventA(NULL, FALSE, FALSE, NULL);
	HANDLE done = CreateEventA(NULL, FALSE, FALSE, NULL);
	TEST_CHECK(acquired && done);

	SharedAcquireContext ctx = {&lock, acquired, done};
	HANDLE thread = CreateThread(NULL, 0, shared_acquire_worker, &ctx, 0, NULL);
	TEST_CHECK(thread != NULL);

	DWORD wait = WaitForSingleObject(acquired, 100);
	TEST_CHECK_EQ(WAIT_TIMEOUT, wait);

	ReleaseSRWLockExclusive(&lock);

	wait = WaitForSingleObject(acquired, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);
	wait = WaitForSingleObject(done, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);
	wait = WaitForSingleObject(thread, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	TEST_CHECK(CloseHandle(thread));
	close_pair(acquired, done);
}

static void test_shared_then_exclusive(void) {
	SRWLOCK lock = SRWLOCK_INIT;
	AcquireSRWLockShared(&lock);

	HANDLE acquired = CreateEventA(NULL, FALSE, FALSE, NULL);
	HANDLE release = CreateEventA(NULL, FALSE, FALSE, NULL);
	HANDLE done = CreateEventA(NULL, FALSE, FALSE, NULL);
	TEST_CHECK(acquired && release && done);

	ExclusiveHoldContext ctx = {&lock, acquired, release, done};
	HANDLE thread = CreateThread(NULL, 0, exclusive_hold_worker, &ctx, 0, NULL);
	TEST_CHECK(thread != NULL);

	DWORD wait = WaitForSingleObject(acquired, 100);
	TEST_CHECK_EQ(WAIT_TIMEOUT, wait);

	ReleaseSRWLockShared(&lock);

	wait = WaitForSingleObject(acquired, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	TEST_CHECK(SetEvent(release));

	wait = WaitForSingleObject(done, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);
	wait = WaitForSingleObject(thread, 2000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	TEST_CHECK(CloseHandle(thread));
	close_pair(acquired, release);
	TEST_CHECK(CloseHandle(done));
}

static void test_try_acquire(void) {
	SRWLOCK lock = SRWLOCK_INIT;

	TEST_CHECK(TryAcquireSRWLockShared(&lock) != 0);
	ReleaseSRWLockShared(&lock);

	TEST_CHECK(TryAcquireSRWLockExclusive(&lock) != 0);
	TEST_CHECK(TryAcquireSRWLockShared(&lock) == 0);
	TEST_CHECK(TryAcquireSRWLockExclusive(&lock) == 0);
	ReleaseSRWLockExclusive(&lock);

	AcquireSRWLockShared(&lock);
	TEST_CHECK(TryAcquireSRWLockExclusive(&lock) == 0);
	ReleaseSRWLockShared(&lock);
}

int main(void) {
	test_shared_readers();
	// test_exclusive_blocks_shared();
	// test_shared_then_exclusive();
	// test_try_acquire();
	return 0;
}
