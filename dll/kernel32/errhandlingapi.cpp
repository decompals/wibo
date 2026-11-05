#include "errhandlingapi.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "internal.h"
#include "kernel32.h"

#include <atomic>

namespace {

std::atomic<LPTOP_LEVEL_EXCEPTION_FILTER> g_topLevelExceptionFilter = nullptr;
UINT g_processErrorMode = 0;

} // namespace

namespace kernel32 {

DWORD getLastError() { return currentThreadTeb->LastErrorValue; }

void setLastError(DWORD error) { currentThreadTeb->LastErrorValue = error; }

void setLastErrorFromErrno() { setLastError(wibo::winErrorFromErrno(errno)); }

DWORD WINAPI GetLastError() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetLastError() -> %u\n", getLastError());
	return currentThreadTeb->LastErrorValue;
}

void WINAPI SetLastError(DWORD dwErrCode) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetLastError(%u)\n", dwErrCode);
	currentThreadTeb->LastErrorValue = dwErrCode;
}

PVOID WINAPI AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: AddVectoredExceptionHandler(%u, %p)\n", First, Handler);
	return reinterpret_cast<PVOID>(Handler);
}

LPTOP_LEVEL_EXCEPTION_FILTER WINAPI
SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetUnhandledExceptionFilter(%p)\n", lpTopLevelExceptionFilter);
	return g_topLevelExceptionFilter.exchange(lpTopLevelExceptionFilter);
}

LONG WINAPI UnhandledExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("UnhandledExceptionFilter(%p)\n", ExceptionInfo);
	const auto *record = fromGuestPtr<EXCEPTION_RECORD>(ExceptionInfo->ExceptionRecord);
	LPTOP_LEVEL_EXCEPTION_FILTER filter = g_topLevelExceptionFilter;
	// A nested call means the top-level filter raised this exception
	if (filter && !(record->ExceptionFlags & EXCEPTION_NESTED_CALL)) {
		LONG result = call_LPTOP_LEVEL_EXCEPTION_FILTER(filter, ExceptionInfo);
		if (result != EXCEPTION_CONTINUE_SEARCH) {
			return result;
		}
	}
	if (record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && record->NumberParameters >= 2) {
		const char *access = "reading";
		if (record->ExceptionInformation[0] == 1) {
			access = "writing";
		} else if (record->ExceptionInformation[0] == 8) {
			access = "executing";
		}
		fprintf(stderr, "wibo: unhandled exception 0x%08x at 0x%08x (%s 0x%08x)\n", record->ExceptionCode,
				record->ExceptionAddress, access, record->ExceptionInformation[1]);
	} else {
		fprintf(stderr, "wibo: unhandled exception 0x%08x at 0x%08x\n", record->ExceptionCode,
				record->ExceptionAddress);
	}
	return EXCEPTION_EXECUTE_HANDLER;
}

UINT WINAPI SetErrorMode(UINT uMode) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: SetErrorMode(%u)\n", uMode);
	UINT previous = g_processErrorMode;
	g_processErrorMode = uMode;
	return previous;
}

} // namespace kernel32
