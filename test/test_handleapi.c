#include "test_assert.h"
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>

static void test_duplicate_handle_basic(void) {
	HANDLE evt = CreateEventA(NULL, TRUE, FALSE, NULL);
	TEST_CHECK(evt != NULL);

	HANDLE dup = NULL;
	BOOL ok = DuplicateHandle(GetCurrentProcess(), evt, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS);
	TEST_CHECK(ok);
	TEST_CHECK(dup != NULL);
	TEST_CHECK(dup != evt);

	TEST_CHECK(SetEvent(evt));
	DWORD waitResult = WaitForSingleObject(dup, 0);
	TEST_CHECK_EQ(WAIT_OBJECT_0, waitResult);
	TEST_CHECK(ResetEvent(evt));

	TEST_CHECK(CloseHandle(dup));
	TEST_CHECK(CloseHandle(evt));
}

static void test_duplicate_handle_close_source(void) {
	HANDLE evt = CreateEventA(NULL, FALSE, FALSE, NULL);
	TEST_CHECK(evt != NULL);

	HANDLE dup = NULL;
	BOOL ok = DuplicateHandle(GetCurrentProcess(), evt, GetCurrentProcess(), &dup, 0, FALSE,
							  DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
	TEST_CHECK(ok);
	TEST_CHECK(dup != NULL);

	// Since we're duplicating within the same process with DUPLICATE_CLOSE_SOURCE,
	// we should get back the same handle value
	TEST_CHECK(dup == evt);

	TEST_CHECK(SetEvent(dup));
	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(dup, 0));
	TEST_CHECK(CloseHandle(dup));
}

static void test_duplicate_handle_invalid_source(void) {
	HANDLE bogus = (HANDLE)(uintptr_t)0x1234;
	HANDLE out = NULL;
	SetLastError(0);
	TEST_CHECK(
		!DuplicateHandle(GetCurrentProcess(), bogus, GetCurrentProcess(), &out, 0, FALSE, DUPLICATE_SAME_ACCESS));
	TEST_CHECK_EQ(ERROR_INVALID_HANDLE, GetLastError());
	TEST_CHECK(out == NULL);
}

static void test_duplicate_handle_invalid_target_process(void) {
	HANDLE evt = CreateEventA(NULL, TRUE, FALSE, NULL);
	TEST_CHECK(evt != NULL);

	HANDLE dup = NULL;
	SetLastError(0xDEADBEEF);
	TEST_CHECK(!DuplicateHandle(GetCurrentProcess(), evt, NULL, &dup, 0, FALSE, DUPLICATE_SAME_ACCESS));
	TEST_CHECK_EQ(ERROR_INVALID_HANDLE, GetLastError());
	TEST_CHECK(dup == NULL);

	TEST_CHECK(CloseHandle(evt));
}

static void test_duplicate_pseudo_process_handle(void) {
	HANDLE pseudo = GetCurrentProcess();
	HANDLE procHandle = NULL;
	BOOL ok = DuplicateHandle(pseudo, pseudo, pseudo, &procHandle, 0, FALSE, DUPLICATE_SAME_ACCESS);
	TEST_CHECK(ok);
	TEST_CHECK(procHandle != NULL);
	TEST_CHECK(procHandle != pseudo);

	TEST_CHECK_EQ(WAIT_TIMEOUT, WaitForSingleObject(procHandle, 0));

	TEST_CHECK(CloseHandle(procHandle));
}

static void test_duplicate_handle_after_close(void) {
	HANDLE evt = CreateEventA(NULL, TRUE, FALSE, NULL);
	TEST_CHECK(evt != NULL);

	TEST_CHECK(CloseHandle(evt));

	HANDLE dup = NULL;
	SetLastError(0);
	TEST_CHECK(!DuplicateHandle(GetCurrentProcess(), evt, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS));
	TEST_CHECK_EQ(ERROR_INVALID_HANDLE, GetLastError());
	TEST_CHECK(dup == NULL);
}

int main(void) {
	test_duplicate_handle_basic();
	test_duplicate_handle_close_source();
	test_duplicate_handle_invalid_source();
	test_duplicate_handle_invalid_target_process();
	test_duplicate_pseudo_process_handle();
	test_duplicate_handle_after_close();
	return EXIT_SUCCESS;
}
