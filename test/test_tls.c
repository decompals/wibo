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
	DWORD tlsExpansionIndex;
	int threadValue;
	int expansionValue;
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

	if (ctx->tlsExpansionIndex != TLS_OUT_OF_INDEXES) {
		DWORD expansionIndex = ctx->tlsExpansionIndex;
		TEST_CHECK(expansionIndex >= TLS_MINIMUM_AVAILABLE);
		void *expansionPtr = &ctx->expansionValue;
		TEST_CHECK(TlsSetValue(expansionIndex, expansionPtr));
		TEST_CHECK_EQ(expansionPtr, TlsGetValue(expansionIndex));
	}

	TEST_CHECK(SetEvent(ctx->readyEvent));

	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(ctx->continueEvent, 1000));

	/* Clear before exit */
	TEST_CHECK(TlsSetValue(ctx->tlsIndex, NULL));
	if (ctx->tlsExpansionIndex != TLS_OUT_OF_INDEXES) {
		TEST_CHECK(TlsSetValue(ctx->tlsExpansionIndex, NULL));
	}
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

	ThreadCtx ctx = {0};
	ctx.tlsIndex = tlsIndex;
	ctx.tlsExpansionIndex = TLS_OUT_OF_INDEXES;
	ctx.threadValue = 0x4242;
	ctx.expansionValue = 0;
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
	tlsArray = tls_slots();
	TEST_CHECK_EQ(mainPtr, TlsGetValue(tlsIndex));
	TEST_CHECK_EQ(mainPtr, tlsArray[tlsIndex]);

	/* Allocate additional slots to cross the TLS_MINIMUM_AVAILABLE boundary */
	const size_t extraCount = 80;
	DWORD extraSlots[extraCount];
	size_t extraUsed = 0;
	DWORD expansionIndex = TLS_OUT_OF_INDEXES;

	for (; extraUsed < extraCount; ++extraUsed) {
		DWORD index = TlsAlloc();
		TEST_CHECK(index != TLS_OUT_OF_INDEXES);
		extraSlots[extraUsed] = index;
		if (index >= TLS_MINIMUM_AVAILABLE) {
			expansionIndex = index;
			++extraUsed;
			break;
		}
	}
	TEST_CHECK(expansionIndex != TLS_OUT_OF_INDEXES);

	tlsArray = tls_slots();

	int mainExpansionValue = 0x5678;
	void *mainExpansionPtr = &mainExpansionValue;
	TEST_CHECK(TlsSetValue(expansionIndex, mainExpansionPtr));
	TEST_CHECK_EQ(mainExpansionPtr, TlsGetValue(expansionIndex));

	ThreadCtx expansionCtx = {0};
	expansionCtx.tlsIndex = tlsIndex;
	expansionCtx.tlsExpansionIndex = expansionIndex;
	expansionCtx.threadValue = 0x3535;
	expansionCtx.expansionValue = 0x2626;
	expansionCtx.readyEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
	expansionCtx.continueEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
	TEST_CHECK(expansionCtx.readyEvent != NULL);
	TEST_CHECK(expansionCtx.continueEvent != NULL);

	thread = CreateThread(NULL, 0, tls_thread_proc, &expansionCtx, 0, NULL);
	TEST_CHECK(thread != NULL);
	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(expansionCtx.readyEvent, 1000));

	tlsArray = tls_slots();
	TEST_CHECK_EQ(mainPtr, TlsGetValue(tlsIndex));
	TEST_CHECK_EQ(mainPtr, tlsArray[tlsIndex]);
	TEST_CHECK_EQ(mainExpansionPtr, TlsGetValue(expansionIndex));

	TEST_CHECK(SetEvent(expansionCtx.continueEvent));
	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(thread, 1000));
	TEST_CHECK(CloseHandle(thread));
	TEST_CHECK(CloseHandle(expansionCtx.readyEvent));
	TEST_CHECK(CloseHandle(expansionCtx.continueEvent));

	/* Ensure worker cleanup didn't disturb main thread values */
	tlsArray = tls_slots();
	TEST_CHECK_EQ(mainPtr, TlsGetValue(tlsIndex));
	TEST_CHECK_EQ(mainPtr, tlsArray[tlsIndex]);
	TEST_CHECK_EQ(mainExpansionPtr, TlsGetValue(expansionIndex));

	/* Clear and free all slots */
	TEST_CHECK(TlsSetValue(tlsIndex, NULL));
	TEST_CHECK(TlsSetValue(expansionIndex, NULL));

	for (size_t i = 0; i < extraUsed; ++i) {
		TEST_CHECK(TlsFree(extraSlots[i]));
	}
	TEST_CHECK(TlsFree(tlsIndex));

	tlsArray = tls_slots();
	TEST_CHECK_EQ(NULL, tlsArray[tlsIndex]);

	return EXIT_SUCCESS;
}
