#include "test_assert.h"

#include <windows.h>

int main(void) {
	SRWLOCK lock;
	InitializeSRWLock(&lock);
	AcquireSRWLockExclusive(&lock);
	TEST_CHECK(!TryAcquireSRWLockExclusive(&lock));
	ReleaseSRWLockExclusive(&lock);
	TEST_CHECK(TryAcquireSRWLockExclusive(&lock));
	ReleaseSRWLockExclusive(&lock);

	HANDLE signaled = CreateEventW(NULL, TRUE, TRUE, NULL);
	HANDLE alsoSignaled = CreateEventW(NULL, TRUE, TRUE, NULL);
	HANDLE unsignaled = CreateEventW(NULL, TRUE, FALSE, NULL);
	TEST_CHECK(signaled && alsoSignaled && unsignaled);

	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObjectEx(signaled, 0, FALSE));
	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObjectEx(signaled, 1000, TRUE));
	TEST_CHECK_EQ(WAIT_TIMEOUT, WaitForSingleObjectEx(unsignaled, 10, FALSE));

	HANDLE both[2] = {signaled, alsoSignaled};
	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForMultipleObjectsEx(2, both, TRUE, 0, FALSE));

	HANDLE mixed[2] = {unsignaled, signaled};
	TEST_CHECK_EQ(WAIT_TIMEOUT, WaitForMultipleObjectsEx(2, mixed, TRUE, 10, FALSE));
	TEST_CHECK_EQ(WAIT_OBJECT_0 + 1, WaitForMultipleObjectsEx(2, mixed, FALSE, 0, TRUE));

	CloseHandle(signaled);
	CloseHandle(alsoSignaled);
	CloseHandle(unsignaled);
	return 0;
}
