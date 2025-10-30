#pragma once

#include "types.h"

constexpr DWORD EXCEPTION_MAXIMUM_PARAMETERS = 15;

struct EXCEPTION_RECORD {
	DWORD ExceptionCode;
	DWORD ExceptionFlags;
	EXCEPTION_RECORD *ExceptionRecord;
	PVOID ExceptionAddress;
	DWORD NumberParameters;
	ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
};

using PEXCEPTION_RECORD = EXCEPTION_RECORD *;
using PCONTEXT = void *;

struct EXCEPTION_POINTERS {
	PEXCEPTION_RECORD ExceptionRecord;
	PCONTEXT ContextRecord;
};

using PEXCEPTION_POINTERS = EXCEPTION_POINTERS *;
using PVECTORED_EXCEPTION_HANDLER = LONG(WIN_FUNC *)(PEXCEPTION_POINTERS ExceptionInfo);
using LPTOP_LEVEL_EXCEPTION_FILTER = LONG(WIN_FUNC *)(PEXCEPTION_POINTERS ExceptionInfo);

constexpr LONG EXCEPTION_CONTINUE_EXECUTION = static_cast<LONG>(-1);
constexpr LONG EXCEPTION_CONTINUE_SEARCH = 0;
constexpr LONG EXCEPTION_EXECUTE_HANDLER = 1;

namespace kernel32 {

DWORD WINAPI GetLastError();
void WINAPI SetLastError(DWORD dwErrCode);
void WINAPI RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments,
						   const ULONG_PTR *lpArguments);
PVOID WINAPI AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
LONG WINAPI UnhandledExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo);
UINT WINAPI SetErrorMode(UINT uMode);

} // namespace kernel32
