#include "test_assert.h"

#include <synchapi.h>
#include <windows.h>

typedef struct {
	volatile LONG *value;
	LONG expected;
	LONG triggerValue;
	HANDLE readyEvent;
	HANDLE doneEvent;
} WaitContext;

static DWORD WINAPI wait_thread(LPVOID param) {
	WaitContext *ctx = (WaitContext *)param;
	TEST_CHECK(SetEvent(ctx->readyEvent));
	BOOL ok = WaitOnAddress((volatile VOID *)ctx->value, &ctx->expected, sizeof(LONG), INFINITE);
	TEST_CHECK(ok);
	TEST_CHECK_EQ(ctx->triggerValue, *ctx->value);
	TEST_CHECK(SetEvent(ctx->doneEvent));
	return 0;
}

static void close_handles(HANDLE *handles, size_t count) {
	for (size_t i = 0; i < count; ++i) {
		if (handles[i]) {
			TEST_CHECK(CloseHandle(handles[i]));
		}
	}
}

static HANDLE create_event(void) {
	HANDLE evt = CreateEventA(NULL, FALSE, FALSE, NULL);
	TEST_CHECK(evt != NULL);
	return evt;
}

static void test_wait_on_address_single(void) {
	volatile LONG value = 0;
	LONG expected = 0;

	HANDLE ready = create_event();
	HANDLE done = create_event();

	WaitContext ctx = {
		.value = &value,
		.expected = expected,
		.triggerValue = 1,
		.readyEvent = ready,
		.doneEvent = done,
	};

	HANDLE thread = CreateThread(NULL, 0, wait_thread, &ctx, 0, NULL);
	TEST_CHECK(thread != NULL);

	DWORD wait = WaitForSingleObject(ready, 1000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	Sleep(10);

	TEST_CHECK_EQ(0, InterlockedExchange((LONG *)&value, ctx.triggerValue));
	WakeByAddressSingle((PVOID)&value);

	wait = WaitForSingleObject(done, 1000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	wait = WaitForSingleObject(thread, 1000);
	TEST_CHECK_EQ(WAIT_OBJECT_0, wait);

	HANDLE handles[] = {thread, ready, done};
	close_handles(handles, sizeof(handles) / sizeof(handles[0]));
}

static void test_wait_on_address_all(void) {
	volatile LONG value = 0;
	const LONG expected = 0;
	const LONG finalValue = 42;

	HANDLE ready[2] = {create_event(), create_event()};
	HANDLE done[2] = {create_event(), create_event()};

	WaitContext ctx[2] = {
		{&value, expected, finalValue, ready[0], done[0]},
		{&value, expected, finalValue, ready[1], done[1]},
	};

	HANDLE threads[2];
	for (int i = 0; i < 2; ++i) {
		threads[i] = CreateThread(NULL, 0, wait_thread, &ctx[i], 0, NULL);
		TEST_CHECK(threads[i] != NULL);
	}

	for (int i = 0; i < 2; ++i) {
		DWORD wait = WaitForSingleObject(ready[i], 1000);
		TEST_CHECK_EQ(WAIT_OBJECT_0, wait);
	}

	Sleep(10);

	TEST_CHECK_EQ(0, InterlockedExchange((LONG *)&value, finalValue));
	WakeByAddressAll((PVOID)&value);

	for (int i = 0; i < 2; ++i) {
		DWORD wait = WaitForSingleObject(done[i], 1000);
		TEST_CHECK_EQ(WAIT_OBJECT_0, wait);
		wait = WaitForSingleObject(threads[i], 1000);
		TEST_CHECK_EQ(WAIT_OBJECT_0, wait);
	}

	HANDLE handles[] = {
		threads[0], threads[1], ready[0], ready[1], done[0], done[1],
	};
	close_handles(handles, sizeof(handles) / sizeof(handles[0]));
}

static void test_wait_on_address_timeout(void) {
	volatile LONG value = 7;
	LONG expected = 7;

	SetLastError(0);
	BOOL ok = WaitOnAddress((volatile VOID *)&value, &expected, sizeof(LONG), 50);
	TEST_CHECK(!ok);
	TEST_CHECK_EQ(ERROR_TIMEOUT, GetLastError());
	TEST_CHECK_EQ(7, value);
}

static void test_wait_on_address_immediate(void) {
	volatile LONG value = 10;
	LONG expected = 11;

	BOOL ok = WaitOnAddress((volatile VOID *)&value, &expected, sizeof(LONG), 1000);
	TEST_CHECK(ok);
	TEST_CHECK_EQ(10, value);
}

int main(void) {
	test_wait_on_address_single();
	test_wait_on_address_all();
	test_wait_on_address_timeout();
	test_wait_on_address_immediate();
	return EXIT_SUCCESS;
}
