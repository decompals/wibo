#include <windows.h>
#include <stdlib.h>
#include "test_assert.h"

typedef struct {
    HANDLE readyEvent;
    HANDLE goEvent;
    DWORD exitCode;
} WorkerContext;

static DWORD WINAPI worker_main(LPVOID param) {
    WorkerContext *ctx = (WorkerContext *)param;
    TEST_CHECK(SetEvent(ctx->readyEvent));
    DWORD waitResult = WaitForSingleObject(ctx->goEvent, INFINITE);
    TEST_CHECK_EQ(WAIT_OBJECT_0, waitResult);
    return ctx->exitCode;
}

static DWORD WINAPI exit_thread_worker(LPVOID param) {
    DWORD code = *(DWORD *)param;
    ExitThread(code);
    return 0; /* unreachable */
}

int main(void) {
    HANDLE readyEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    TEST_CHECK(readyEvent != NULL);

    HANDLE goEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    TEST_CHECK(goEvent != NULL);

    WorkerContext ctx;
    ctx.readyEvent = readyEvent;
    ctx.goEvent = goEvent;
    ctx.exitCode = 0x1234;

    HANDLE thread = CreateThread(NULL, 0, worker_main, &ctx, 0, NULL);
    TEST_CHECK(thread != NULL);

    DWORD waitResult = WaitForSingleObject(readyEvent, INFINITE);
    TEST_CHECK_EQ(WAIT_OBJECT_0, waitResult);

    TEST_CHECK(ResetEvent(readyEvent));

    TEST_CHECK(SetEvent(goEvent));

    waitResult = WaitForSingleObject(thread, INFINITE);
    TEST_CHECK_EQ(WAIT_OBJECT_0, waitResult);

    DWORD exitCode = 0;
    TEST_CHECK(GetExitCodeThread(thread, &exitCode));
    TEST_CHECK_EQ(ctx.exitCode, exitCode);

    TEST_CHECK(CloseHandle(thread));

    HANDLE autoEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    TEST_CHECK(autoEvent != NULL);
    TEST_CHECK(SetEvent(autoEvent));
    waitResult = WaitForSingleObject(autoEvent, INFINITE);
    TEST_CHECK_EQ(WAIT_OBJECT_0, waitResult);
    TEST_CHECK(SetEvent(autoEvent));
    waitResult = WaitForSingleObject(autoEvent, INFINITE);
    TEST_CHECK_EQ(WAIT_OBJECT_0, waitResult);
    TEST_CHECK(CloseHandle(autoEvent));

    HANDLE manualEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    TEST_CHECK(manualEvent != NULL);
    TEST_CHECK(SetEvent(manualEvent));
    waitResult = WaitForSingleObject(manualEvent, INFINITE);
    TEST_CHECK_EQ(WAIT_OBJECT_0, waitResult);
    TEST_CHECK(ResetEvent(manualEvent));
    TEST_CHECK(SetEvent(manualEvent));
    waitResult = WaitForSingleObject(manualEvent, INFINITE);
    TEST_CHECK_EQ(WAIT_OBJECT_0, waitResult);
    TEST_CHECK(CloseHandle(manualEvent));

    DWORD selfExitCode = 0;
    TEST_CHECK(GetExitCodeThread(GetCurrentThread(), &selfExitCode));
    TEST_CHECK_EQ(STILL_ACTIVE, selfExitCode);

    HANDLE mutex = CreateMutexA(NULL, FALSE, NULL);
    TEST_CHECK(mutex != NULL);
    waitResult = WaitForSingleObject(mutex, INFINITE);
    TEST_CHECK_EQ(WAIT_OBJECT_0, waitResult);
    TEST_CHECK(ReleaseMutex(mutex));
    TEST_CHECK(CloseHandle(mutex));

    DWORD secondExitCode = 0x55AA;
    HANDLE exitThread = CreateThread(NULL, 0, exit_thread_worker, &secondExitCode, 0, NULL);
    TEST_CHECK(exitThread != NULL);
    waitResult = WaitForSingleObject(exitThread, INFINITE);
    TEST_CHECK_EQ(WAIT_OBJECT_0, waitResult);
    exitCode = 0;
    TEST_CHECK(GetExitCodeThread(exitThread, &exitCode));
    TEST_CHECK_EQ(secondExitCode, exitCode);
    TEST_CHECK(CloseHandle(exitThread));

    TEST_CHECK(CloseHandle(goEvent));
    TEST_CHECK(CloseHandle(readyEvent));

    return EXIT_SUCCESS;
}
