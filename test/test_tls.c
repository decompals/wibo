#include "test_assert.h"
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>

static void *current_teb(void) {
	void *teb = NULL;
	__asm__ __volatile__("movl %%fs:0x18, %0" : "=r"(teb));
	return teb;
}

static void **tls_slots(void) {
	uint8_t *teb = (uint8_t *)current_teb();
	return (void **)(teb + 0xE10);
}

typedef struct {
	DWORD tlsIndex;
	int threadValue;
	HANDLE readyEvent;
	HANDLE continueEvent;
} ThreadCtx;

static DWORD WINAPI tls_thread_proc(LPVOID param) {
	ThreadCtx *ctx = (ThreadCtx *)param;
	TEST_CHECK(ctx != NULL);

	/* TLS initially zero for a new thread */
	TEST_CHECK_EQ(NULL, TlsGetValue(ctx->tlsIndex));
	TEST_CHECK_EQ(NULL, tls_slots()[ctx->tlsIndex]);

	void *threadPtr = &ctx->threadValue;
	TEST_CHECK(TlsSetValue(ctx->tlsIndex, threadPtr));
	TEST_CHECK_EQ(threadPtr, TlsGetValue(ctx->tlsIndex));
	TEST_CHECK_EQ(threadPtr, tls_slots()[ctx->tlsIndex]);

	TEST_CHECK(SetEvent(ctx->readyEvent));

	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(ctx->continueEvent, 1000));

	/* Clear before exit */
	TEST_CHECK(TlsSetValue(ctx->tlsIndex, NULL));
	return 0;
}

int main(void) {
	DWORD tlsIndex = TlsAlloc();
	TEST_CHECK(tlsIndex != TLS_OUT_OF_INDEXES);

	TEST_CHECK_EQ(NULL, TlsGetValue(tlsIndex));

	void **tlsArray = tls_slots();
	TEST_CHECK(tlsArray != NULL);

	int mainValue = 12345;
	void *mainPtr = &mainValue;
	TEST_CHECK(TlsSetValue(tlsIndex, mainPtr));
	TEST_CHECK_EQ(mainPtr, TlsGetValue(tlsIndex));
	TEST_CHECK_EQ(mainPtr, tlsArray[tlsIndex]);

	ThreadCtx ctx;
	ctx.tlsIndex = tlsIndex;
	ctx.threadValue = 0x4242;
	ctx.readyEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
	ctx.continueEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
	TEST_CHECK(ctx.readyEvent != NULL);
	TEST_CHECK(ctx.continueEvent != NULL);

	HANDLE thread = CreateThread(NULL, 0, tls_thread_proc, &ctx, 0, NULL);
	TEST_CHECK(thread != NULL);

	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(ctx.readyEvent, 1000));

	/* Main thread value should be unchanged by worker */
	TEST_CHECK_EQ(mainPtr, TlsGetValue(tlsIndex));
	TEST_CHECK_EQ(mainPtr, tlsArray[tlsIndex]);

	TEST_CHECK(SetEvent(ctx.continueEvent));

	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(thread, 1000));
	TEST_CHECK(CloseHandle(thread));

	TEST_CHECK(CloseHandle(ctx.readyEvent));
	TEST_CHECK(CloseHandle(ctx.continueEvent));

	/* Ensure worker cleanup didn't disturb main thread */
	TEST_CHECK_EQ(mainPtr, TlsGetValue(tlsIndex));
	TEST_CHECK_EQ(mainPtr, tlsArray[tlsIndex]);

	TEST_CHECK(TlsSetValue(tlsIndex, NULL));
	TEST_CHECK_EQ(NULL, TlsGetValue(tlsIndex));
	TEST_CHECK(TlsFree(tlsIndex));
	TEST_CHECK_EQ(NULL, tlsArray[tlsIndex]);

	return EXIT_SUCCESS;
}
