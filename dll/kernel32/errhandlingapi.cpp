#include "errhandlingapi.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "internal.h"

namespace {

LPTOP_LEVEL_EXCEPTION_FILTER g_topLevelExceptionFilter = nullptr;
UINT g_processErrorMode = 0;

} // namespace

namespace kernel32 {

DWORD getLastError() { return wibo::getThreadTibForHost()->lastErrorValue; }

void setLastError(DWORD error) { wibo::getThreadTibForHost()->lastErrorValue = error; }

void setLastErrorFromErrno() { setLastError(wibo::winErrorFromErrno(errno)); }

DWORD WIN_FUNC GetLastError() {
#ifndef NDEBUG
	{
		HOST_CONTEXT_GUARD();
		DEBUG_LOG("GetLastError() -> %u\n", getLastError());
	}
#endif
	// In guest context, fetch via TIB
	DWORD err;
	__asm__ __volatile__("movl %%fs:%c1, %0" : "=r"(err) : "i"(offsetof(TIB, lastErrorValue)));
	return err;
}

void WIN_FUNC SetLastError(DWORD dwErrCode) {
#ifndef NDEBUG
	{
		HOST_CONTEXT_GUARD();
		DEBUG_LOG("SetLastError(%u)\n", dwErrCode);
	}
#endif
	// In guest context, store via TIB
	__asm__ __volatile__("movl %0, %%fs:%c1" : : "r"(dwErrCode), "i"(offsetof(TIB, lastErrorValue)) : "memory");
}

void WIN_FUNC RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments,
							 const ULONG_PTR *lpArguments) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("RaiseException(0x%x, 0x%x, %u, %p)\n", dwExceptionCode, dwExceptionFlags, nNumberOfArguments,
			  lpArguments);
	(void)dwExceptionFlags;
	(void)nNumberOfArguments;
	(void)lpArguments;
	exitInternal(dwExceptionCode);
}

PVOID WIN_FUNC AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: AddVectoredExceptionHandler(%u, %p)\n", First, Handler);
	return reinterpret_cast<PVOID>(Handler);
}

LPTOP_LEVEL_EXCEPTION_FILTER WIN_FUNC
SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: SetUnhandledExceptionFilter(%p)\n", lpTopLevelExceptionFilter);
	LPTOP_LEVEL_EXCEPTION_FILTER previous = g_topLevelExceptionFilter;
	g_topLevelExceptionFilter = lpTopLevelExceptionFilter;
	return previous;
}

LONG WIN_FUNC UnhandledExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: UnhandledExceptionFilter(%p)\n", ExceptionInfo);
	return EXCEPTION_EXECUTE_HANDLER;
}

UINT WIN_FUNC SetErrorMode(UINT uMode) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: SetErrorMode(%u)\n", uMode);
	UINT previous = g_processErrorMode;
	g_processErrorMode = uMode;
	return previous;
}

} // namespace kernel32
