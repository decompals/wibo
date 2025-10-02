#include "common.h"
#include "kernel32.h"

namespace {
LPTOP_LEVEL_EXCEPTION_FILTER g_topLevelExceptionFilter = nullptr;
UINT g_processErrorMode = 0;
} // namespace

namespace kernel32 {

DWORD WIN_FUNC GetLastError() {
	DEBUG_LOG("GetLastError() -> %u\n", wibo::lastError);
	return wibo::lastError;
}

void WIN_FUNC SetLastError(DWORD dwErrCode) {
	DEBUG_LOG("SetLastError(%u)\n", dwErrCode);
	wibo::lastError = dwErrCode;
}

void WIN_FUNC RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments,
							 const ULONG_PTR *lpArguments) {
	DEBUG_LOG("RaiseException(0x%x, 0x%x, %u, %p)\n", dwExceptionCode, dwExceptionFlags, nNumberOfArguments,
			  lpArguments);
	(void)dwExceptionFlags;
	(void)nNumberOfArguments;
	(void)lpArguments;
	exit(static_cast<int>(dwExceptionCode));
}

PVOID WIN_FUNC AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler) {
	DEBUG_LOG("STUB: AddVectoredExceptionHandler(%u, %p)\n", First, Handler);
	return reinterpret_cast<PVOID>(Handler);
}

LPTOP_LEVEL_EXCEPTION_FILTER WIN_FUNC
SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter) {
	DEBUG_LOG("STUB: SetUnhandledExceptionFilter(%p)\n", lpTopLevelExceptionFilter);
	LPTOP_LEVEL_EXCEPTION_FILTER previous = g_topLevelExceptionFilter;
	g_topLevelExceptionFilter = lpTopLevelExceptionFilter;
	return previous;
}

LONG WIN_FUNC UnhandledExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo) {
	DEBUG_LOG("STUB: UnhandledExceptionFilter(%p)\n", ExceptionInfo);
	return EXCEPTION_EXECUTE_HANDLER;
}

UINT WIN_FUNC SetErrorMode(UINT uMode) {
	DEBUG_LOG("STUB: SetErrorMode(%u)\n", uMode);
	UINT previous = g_processErrorMode;
	g_processErrorMode = uMode;
	return previous;
}

} // namespace kernel32
