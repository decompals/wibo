#include "test_assert.h"

#include <windows.h>

static LONG g_calls;

static BOOL CALLBACK succeeding_init(PINIT_ONCE once, PVOID parameter, PVOID *context) {
	(void)once;
	g_calls++;
	if (context) {
		*context = parameter;
	}
	return TRUE;
}

static BOOL CALLBACK failing_init(PINIT_ONCE once, PVOID parameter, PVOID *context) {
	(void)once;
	(void)parameter;
	(void)context;
	g_calls++;
	return FALSE;
}

int main(void) {
	INIT_ONCE once = INIT_ONCE_STATIC_INIT;
	PVOID context = NULL;
	TEST_CHECK(InitOnceExecuteOnce(&once, succeeding_init, (PVOID)0x1230, &context));
	TEST_CHECK_EQ(1, g_calls);
	TEST_CHECK(context == (PVOID)0x1230);

	context = NULL;
	TEST_CHECK(InitOnceExecuteOnce(&once, succeeding_init, (PVOID)0x4560, &context));
	TEST_CHECK_EQ(1, g_calls);
	TEST_CHECK(context == (PVOID)0x1230);

	INIT_ONCE retry = INIT_ONCE_STATIC_INIT;
	TEST_CHECK(!InitOnceExecuteOnce(&retry, failing_init, NULL, NULL));
	TEST_CHECK_EQ(2, g_calls);
	TEST_CHECK(InitOnceExecuteOnce(&retry, succeeding_init, (PVOID)0x80, NULL));
	TEST_CHECK_EQ(3, g_calls);
	return 0;
}
