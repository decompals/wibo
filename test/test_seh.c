#include <stdint.h>
#include <windows.h>

#include "test_assert.h"

#define PAGE_SIZE 0x1000
#define REGION_PAGES 16
#define CXX_EXCEPTION 0xE06D7363
#define CUSTOM_EXCEPTION 0xE0000001
#define NESTED_EXCEPTION 0xE0000002

typedef struct Registration {
	struct Registration *next;
	void *handler;
} Registration;

static Registration *chainHead(void) {
	Registration *head;
	__asm__ volatile("movl %%fs:0, %0" : "=r"(head));
	return head;
}

static void setChainHead(Registration *head) { __asm__ volatile("movl %0, %%fs:0" : : "r"(head) : "memory"); }

static void pushHandler(Registration *reg, void *handler) {
	reg->handler = handler;
	reg->next = chainHead();
	setChainHead(reg);
}

static char *g_region;
static int g_commits;

// What MSVC's c1xx does: reserve a buffer, commit pages as writes fault on them
static EXCEPTION_DISPOSITION __cdecl commitOnWrite(EXCEPTION_RECORD *record, void *frame, CONTEXT *context,
												   void *dispatcherContext) {
	(void)frame;
	(void)dispatcherContext;
	if (record->ExceptionFlags & EXCEPTION_UNWINDING) {
		return ExceptionContinueSearch;
	}
	if (record->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || record->NumberParameters != 2 ||
		record->ExceptionInformation[0] != 1) {
		return ExceptionContinueSearch;
	}
	char *address = (char *)record->ExceptionInformation[1];
	if (address < g_region || address >= g_region + REGION_PAGES * PAGE_SIZE) {
		return ExceptionContinueSearch;
	}
	TEST_CHECK_EQ((uintptr_t)record->ExceptionAddress, context->Eip);
	if (!VirtualAlloc(address, 1, MEM_COMMIT, PAGE_READWRITE)) {
		return ExceptionContinueSearch;
	}
	g_commits++;
	return ExceptionContinueExecution;
}

static void testCommitOnWrite(void) {
	g_region = VirtualAlloc(NULL, REGION_PAGES * PAGE_SIZE, MEM_RESERVE, PAGE_NOACCESS);
	TEST_CHECK(g_region != NULL);
	g_commits = 0;
	Registration reg;
	pushHandler(&reg, commitOnWrite);
	for (int i = 0; i < REGION_PAGES; i++) {
		((volatile char *)g_region)[i * PAGE_SIZE + 7] = (char)(i + 1);
	}
	setChainHead(reg.next);
	TEST_CHECK_EQ(REGION_PAGES, g_commits);
	for (int i = 0; i < REGION_PAGES; i++) {
		TEST_CHECK_EQ(i + 1, g_region[i * PAGE_SIZE + 7]);
	}
	TEST_CHECK(VirtualFree(g_region, 0, MEM_RELEASE));
}

__attribute__((target("sse2"))) static void testStateSurvivesFault(void) {
	g_region = VirtualAlloc(NULL, REGION_PAGES * PAGE_SIZE, MEM_RESERVE, PAGE_NOACCESS);
	TEST_CHECK(g_region != NULL);
	g_commits = 0;
	Registration reg;
	pushHandler(&reg, commitOnWrite);
	double x87Sum;
	uint32_t xmm, ecx, edx, esi, edi;
	__asm__ volatile(
		"fld1\n\t"
		"fldpi\n\t"
		"movd %[xmmIn], %%xmm1\n\t"
		"movl $0x11111111, %%ecx\n\t"
		"movl $0x22222222, %%edx\n\t"
		"movl $0x33333333, %%esi\n\t"
		"movl $0x44444444, %%edi\n\t"
		"movb $1, (%%eax)\n\t"
		"faddp\n\t"
		"fstpl %[x87Sum]\n\t"
		"movd %%xmm1, %[xmm]\n\t"
		"movl %%ecx, %[ecx]\n\t"
		"movl %%edx, %[edx]\n\t"
		"movl %%esi, %[esi]\n\t"
		"movl %%edi, %[edi]"
		: [x87Sum] "=m"(x87Sum), [xmm] "=m"(xmm), [ecx] "=m"(ecx), [edx] "=m"(edx), [esi] "=m"(esi), [edi] "=m"(edi)
		: [xmmIn] "r"(0x5a5a5a5a), "a"(g_region + PAGE_SIZE)
		: "ecx", "edx", "esi", "edi", "xmm1", "memory");
	setChainHead(reg.next);
	TEST_CHECK_EQ(1, g_commits);
	TEST_CHECK(x87Sum > 4.14159 && x87Sum < 4.1416);
	TEST_CHECK_U64_EQ(0x5a5a5a5a, xmm);
	TEST_CHECK_U64_EQ(0x11111111, ecx);
	TEST_CHECK_U64_EQ(0x22222222, edx);
	TEST_CHECK_U64_EQ(0x33333333, esi);
	TEST_CHECK_U64_EQ(0x44444444, edi);
	TEST_CHECK(VirtualFree(g_region, 0, MEM_RELEASE));
}

static int g_divides;

static EXCEPTION_DISPOSITION __cdecl skipDivide(EXCEPTION_RECORD *record, void *frame, CONTEXT *context,
												void *dispatcherContext) {
	(void)frame;
	(void)dispatcherContext;
	if (record->ExceptionCode != EXCEPTION_INT_DIVIDE_BY_ZERO) {
		return ExceptionContinueSearch;
	}
	context->Eax = 42;
	context->Eip += 2; // divl %ecx
	g_divides++;
	return ExceptionContinueExecution;
}

static uint32_t divideByZero(void) {
	uint32_t result;
	__asm__ volatile("xorl %%edx, %%edx\n\t"
					 "movl $7, %%eax\n\t"
					 "xorl %%ecx, %%ecx\n\t"
					 "divl %%ecx"
					 : "=a"(result)
					 :
					 : "ecx", "edx");
	return result;
}

static void testContextChanges(void) {
	Registration reg;
	pushHandler(&reg, skipDivide);
	TEST_CHECK_EQ(42, divideByZero());
	setChainHead(reg.next);
	TEST_CHECK_EQ(1, g_divides);
}

static int g_raises;

static EXCEPTION_DISPOSITION __cdecl continueRaise(EXCEPTION_RECORD *record, void *frame, CONTEXT *context,
												   void *dispatcherContext) {
	(void)frame;
	(void)context;
	(void)dispatcherContext;
	if (record->ExceptionCode != CUSTOM_EXCEPTION) {
		return ExceptionContinueSearch;
	}
	TEST_CHECK_EQ(0, record->ExceptionFlags);
	TEST_CHECK_EQ(2, record->NumberParameters);
	TEST_CHECK_EQ(0x1234, record->ExceptionInformation[0]);
	TEST_CHECK_EQ(0x5678, record->ExceptionInformation[1]);
	g_raises++;
	return ExceptionContinueExecution;
}

static void testRaiseContinue(void) {
	Registration reg;
	pushHandler(&reg, continueRaise);
	const ULONG_PTR args[2] = {0x1234, 0x5678};
	RaiseException(CUSTOM_EXCEPTION, 0, 2, args);
	setChainHead(reg.next);
	TEST_CHECK_EQ(1, g_raises);
}

static DWORD g_nestedFlags[2];

// Raises a second exception while handling the first
static EXCEPTION_DISPOSITION __cdecl raiseNested(EXCEPTION_RECORD *record, void *frame, CONTEXT *context,
												 void *dispatcherContext) {
	(void)frame;
	(void)context;
	(void)dispatcherContext;
	if (record->ExceptionCode == NESTED_EXCEPTION) {
		g_nestedFlags[0] = record->ExceptionFlags;
		return ExceptionContinueSearch;
	}
	if (record->ExceptionCode != CUSTOM_EXCEPTION) {
		return ExceptionContinueSearch;
	}
	RaiseException(NESTED_EXCEPTION, 0, 0, NULL);
	return ExceptionContinueExecution;
}

static EXCEPTION_DISPOSITION __cdecl continueNested(EXCEPTION_RECORD *record, void *frame, CONTEXT *context,
													void *dispatcherContext) {
	(void)frame;
	(void)context;
	(void)dispatcherContext;
	if (record->ExceptionCode != NESTED_EXCEPTION) {
		return ExceptionContinueSearch;
	}
	g_nestedFlags[1] = record->ExceptionFlags;
	return ExceptionContinueExecution;
}

// Registrations must be ordered by address, so the inner one lives in a deeper frame
__attribute__((noinline)) static void raiseWithNestedHandler(void) {
	Registration inner;
	pushHandler(&inner, raiseNested);
	RaiseException(CUSTOM_EXCEPTION, 0, 0, NULL);
	setChainHead(inner.next);
}

static void testNested(void) {
	Registration outer;
	pushHandler(&outer, continueNested);
	raiseWithNestedHandler();
	setChainHead(outer.next);
	// Only frames up to the one whose handler raised it see the exception as nested
	TEST_CHECK(g_nestedFlags[0] & EXCEPTION_NESTED_CALL);
	TEST_CHECK(!(g_nestedFlags[1] & EXCEPTION_NESTED_CALL));
}

static void *g_jumpBuffer[5];
static DWORD g_expectedCode;
static int g_unwound;
static int g_caught;

static EXCEPTION_DISPOSITION __cdecl innerHandler(EXCEPTION_RECORD *record, void *frame, CONTEXT *context,
												  void *dispatcherContext) {
	(void)frame;
	(void)context;
	(void)dispatcherContext;
	if (record->ExceptionFlags & EXCEPTION_UNWINDING) {
		g_unwound++;
	}
	return ExceptionContinueSearch;
}

// The shape of an __except block: unwind the inner frames, then jump into the handler's frame
static EXCEPTION_DISPOSITION __cdecl catchAndJump(EXCEPTION_RECORD *record, void *frame, CONTEXT *context,
												  void *dispatcherContext) {
	(void)context;
	(void)dispatcherContext;
	if ((record->ExceptionFlags & EXCEPTION_UNWINDING) || record->ExceptionCode != g_expectedCode) {
		return ExceptionContinueSearch;
	}
	g_caught++;
	RtlUnwind(frame, NULL, record, NULL);
	__builtin_longjmp(g_jumpBuffer, 1);
}

__attribute__((noinline)) static void catchFrom(DWORD code, void (*raise)(void *), void *param) {
	Registration outer;
	g_expectedCode = code;
	if (__builtin_setjmp(g_jumpBuffer) == 0) {
		pushHandler(&outer, catchAndJump);
		raise(param);
		TEST_FAIL("exception 0x%lx was not raised", code);
	}
	TEST_CHECK(chainHead() == &outer);
	setChainHead(outer.next);
}

static void runThread(LPTHREAD_START_ROUTINE start, void *param) {
	HANDLE thread = CreateThread(NULL, 0, start, param, 0, NULL);
	TEST_CHECK(thread != NULL);
	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(thread, INFINITE));
	DWORD exitCode = 0;
	TEST_CHECK(GetExitCodeThread(thread, &exitCode));
	TEST_CHECK_EQ(7, exitCode);
	TEST_CHECK(CloseHandle(thread));
}

// Registrations must be ordered by address, so the inner one lives in a deeper frame
__attribute__((noinline)) static void raiseFromInnerFrame(void *noAccess) {
	Registration inner;
	pushHandler(&inner, innerHandler);
	if (g_expectedCode == CXX_EXCEPTION) {
		RaiseException(CXX_EXCEPTION, EXCEPTION_NONCONTINUABLE, 0, NULL);
	} else {
		*(volatile char *)noAccess = 1;
	}
}

static DWORD WINAPI unwindThread(LPVOID param) {
	// Repeated catches would exhaust the stack if dispatching leaked any of it
	for (int i = 0; i < 2000; i++) {
		catchFrom(i % 2 ? CXX_EXCEPTION : EXCEPTION_ACCESS_VIOLATION, raiseFromInnerFrame, param);
	}
	return 7;
}

static void testUnwind(void) {
	char *noAccess = VirtualAlloc(NULL, PAGE_SIZE, MEM_RESERVE, PAGE_NOACCESS);
	TEST_CHECK(noAccess != NULL);
	g_unwound = 0;
	g_caught = 0;
	catchFrom(EXCEPTION_ACCESS_VIOLATION, raiseFromInnerFrame, noAccess);
	catchFrom(CXX_EXCEPTION, raiseFromInnerFrame, noAccess);
	TEST_CHECK_EQ(2, g_caught);
	TEST_CHECK_EQ(2, g_unwound);

	// The thread returns to host code, which needs the host stack left consistent
	runThread(unwindThread, noAccess);
	TEST_CHECK_EQ(2002, g_caught);
	TEST_CHECK_EQ(2002, g_unwound);
	TEST_CHECK(VirtualFree(noAccess, 0, MEM_RELEASE));
}

static EXCEPTION_DISPOSITION __cdecl continueCustom(EXCEPTION_RECORD *record, void *frame, CONTEXT *context,
													void *dispatcherContext) {
	(void)frame;
	(void)context;
	(void)dispatcherContext;
	return record->ExceptionCode == CUSTOM_EXCEPTION ? ExceptionContinueExecution : ExceptionContinueSearch;
}

__attribute__((noinline)) static void continueNoncontinuable(void *param) {
	(void)param;
	Registration inner;
	pushHandler(&inner, continueCustom);
	RaiseException(CUSTOM_EXCEPTION, EXCEPTION_NONCONTINUABLE, 0, NULL);
}

static void testNoncontinuable(void) {
	g_caught = 0;
	catchFrom(EXCEPTION_NONCONTINUABLE_EXCEPTION, continueNoncontinuable, NULL);
	TEST_CHECK_EQ(1, g_caught);
}

__attribute__((noinline)) static void overflowStack(void *depth) {
	volatile char block[256];
	block[0] = 0;
	if ((uintptr_t)depth < 0x100000) {
		overflowStack((char *)depth + 1);
	}
	(void)block[0];
}

static DWORD WINAPI overflowThread(LPVOID param) {
	(void)param;
	catchFrom(EXCEPTION_STACK_OVERFLOW, overflowStack, NULL);
	return 7;
}

static void testStackOverflow(void) {
	g_caught = 0;
	// On a thread of its own, since the overflow uses up the guard page
	runThread(overflowThread, NULL);
	TEST_CHECK_EQ(1, g_caught);
}

static BOOL CALLBACK raiseFromLocale(LPSTR locale) {
	(void)locale;
	RaiseException(CUSTOM_EXCEPTION, 0, 0, NULL);
	return TRUE;
}

static void enumerateLocales(void *param) {
	(void)param;
	EnumSystemLocalesA(raiseFromLocale, LCID_INSTALLED);
}

static DWORD WINAPI callbackThread(LPVOID param) {
	(void)param;
	catchFrom(CUSTOM_EXCEPTION, enumerateLocales, NULL);
	return 7;
}

static void testCallbackUnwind(void) {
	g_caught = 0;
	// The catch abandons the API's host frames, and the thread still returns to host code
	runThread(callbackThread, NULL);
	TEST_CHECK_EQ(1, g_caught);
}

static int g_filterCalls;

static LONG WINAPI topLevelFilter(EXCEPTION_POINTERS *info) {
	if (info->ExceptionRecord->ExceptionCode != EXCEPTION_INT_DIVIDE_BY_ZERO) {
		return EXCEPTION_CONTINUE_SEARCH;
	}
	info->ContextRecord->Eax = 99;
	info->ContextRecord->Eip += 2; // divl %ecx
	g_filterCalls++;
	return EXCEPTION_CONTINUE_EXECUTION;
}

static void testUnhandledFilter(void) {
	LPTOP_LEVEL_EXCEPTION_FILTER previous = SetUnhandledExceptionFilter(topLevelFilter);
	TEST_CHECK_EQ(99, divideByZero());
	SetUnhandledExceptionFilter(previous);
	TEST_CHECK_EQ(1, g_filterCalls);
}

int main(void) {
	Registration *reg = chainHead();
	while (reg != (Registration *)-1) {
		TEST_CHECK(reg != NULL);
		reg = reg->next;
	}
	testCommitOnWrite();
	testStateSurvivesFault();
	testContextChanges();
	testRaiseContinue();
	testNested();
	testUnwind();
	testNoncontinuable();
	testStackOverflow();
	testCallbackUnwind();
	testUnhandledFilter();
	return EXIT_SUCCESS;
}
