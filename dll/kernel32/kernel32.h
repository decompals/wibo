#pragma once

#include "common.h"

// errhandlingapi.h
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

// synchapi.h constants
constexpr DWORD WAIT_OBJECT_0 = 0x00000000;
constexpr DWORD WAIT_ABANDONED = 0x00000080;
constexpr DWORD WAIT_TIMEOUT = 0x00000102;
constexpr DWORD WAIT_FAILED = 0xFFFFFFFF;
constexpr DWORD INFINITE = 0xFFFFFFFF;

// minwinbase.h
struct SECURITY_ATTRIBUTES {
	DWORD nLength;
	LPVOID lpSecurityDescriptor;
	BOOL bInheritHandle;
};

using PSECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES *;
using LPSECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES *;

// sysinfoapi.h
struct SYSTEM_INFO {
	union {
		DWORD dwOemId;
		struct {
			WORD wProcessorArchitecture;
			WORD wReserved;
		};
	};
	DWORD dwPageSize;
	LPVOID lpMinimumApplicationAddress;
	LPVOID lpMaximumApplicationAddress;
	DWORD_PTR dwActiveProcessorMask;
	DWORD dwNumberOfProcessors;
	DWORD dwProcessorType;
	DWORD dwAllocationGranularity;
	WORD wProcessorLevel;
	WORD wProcessorRevision;
};

using LPSYSTEM_INFO = SYSTEM_INFO *;

// processthreadsapi.h
struct PROCESS_INFORMATION {
	HANDLE hProcess;
	HANDLE hThread;
	DWORD dwProcessId;
	DWORD dwThreadId;
};

using PPROCESS_INFORMATION = PROCESS_INFORMATION *;
using LPPROCESS_INFORMATION = PROCESS_INFORMATION *;

struct STARTUPINFOA {
	DWORD cb;
	LPSTR lpReserved;
	LPSTR lpDesktop;
	LPSTR lpTitle;
	DWORD dwX;
	DWORD dwY;
	DWORD dwXSize;
	DWORD dwYSize;
	DWORD dwXCountChars;
	DWORD dwYCountChars;
	DWORD dwFillAttribute;
	DWORD dwFlags;
	WORD wShowWindow;
	WORD cbReserved2;
	unsigned char *lpReserved2;
	HANDLE hStdInput;
	HANDLE hStdOutput;
	HANDLE hStdError;
};

using LPSTARTUPINFOA = STARTUPINFOA *;

struct STARTUPINFOW {
	DWORD cb;
	LPWSTR lpReserved;
	LPWSTR lpDesktop;
	LPWSTR lpTitle;
	DWORD dwX;
	DWORD dwY;
	DWORD dwXSize;
	DWORD dwYSize;
	DWORD dwXCountChars;
	DWORD dwYCountChars;
	DWORD dwFillAttribute;
	DWORD dwFlags;
	WORD wShowWindow;
	WORD cbReserved2;
	unsigned char *lpReserved2;
	HANDLE hStdInput;
	HANDLE hStdOutput;
	HANDLE hStdError;
};

using LPSTARTUPINFOW = STARTUPINFOW *;

// fibersapi.h
using PFLS_CALLBACK_FUNCTION = void (*)(void *);
constexpr DWORD FLS_OUT_OF_INDEXES = 0xFFFFFFFF;

namespace kernel32 {

// fibersapi.h
DWORD WIN_FUNC FlsAlloc(PFLS_CALLBACK_FUNCTION lpCallback);
BOOL WIN_FUNC FlsFree(DWORD dwFlsIndex);
PVOID WIN_FUNC FlsGetValue(DWORD dwFlsIndex);
BOOL WIN_FUNC FlsSetValue(DWORD dwFlsIndex, PVOID lpFlsData);

// errhandlingapi.h
DWORD WIN_FUNC GetLastError();
void WIN_FUNC SetLastError(DWORD dwErrCode);
void WIN_FUNC RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments,
							 const ULONG_PTR *lpArguments);
PVOID WIN_FUNC AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
LPTOP_LEVEL_EXCEPTION_FILTER WIN_FUNC
SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);
LONG WIN_FUNC UnhandledExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo);
UINT WIN_FUNC SetErrorMode(UINT uMode);

// wow64apiset.h
BOOL WIN_FUNC Wow64DisableWow64FsRedirection(PVOID *OldValue);
BOOL WIN_FUNC Wow64RevertWow64FsRedirection(PVOID OldValue);
BOOL WIN_FUNC IsWow64Process(HANDLE hProcess, PBOOL Wow64Process);

// sysinfoapi.h
void WIN_FUNC GetSystemInfo(LPSYSTEM_INFO lpSystemInfo);

// processthreadsapi.h
HANDLE WIN_FUNC GetCurrentProcess();
DWORD WIN_FUNC GetCurrentProcessId();
DWORD WIN_FUNC GetCurrentThreadId();
BOOL WIN_FUNC GetProcessAffinityMask(HANDLE hProcess, PDWORD_PTR lpProcessAffinityMask, PDWORD_PTR lpSystemAffinityMask);
BOOL WIN_FUNC SetProcessAffinityMask(HANDLE hProcess, DWORD_PTR dwProcessAffinityMask);
void WIN_FUNC ExitProcess(UINT uExitCode);
BOOL WIN_FUNC TerminateProcess(HANDLE hProcess, UINT uExitCode);
BOOL WIN_FUNC GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode);
BOOL WIN_FUNC CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
				 LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
				 LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
				 LPPROCESS_INFORMATION lpProcessInformation);
BOOL WIN_FUNC CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
					 LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
					 LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
					 LPPROCESS_INFORMATION lpProcessInformation);

// synchapi.h
HANDLE WIN_FUNC CreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName);
HANDLE WIN_FUNC CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName);
BOOL WIN_FUNC ReleaseMutex(HANDLE hMutex);
HANDLE WIN_FUNC CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
HANDLE WIN_FUNC CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName);
BOOL WIN_FUNC SetEvent(HANDLE hEvent);
BOOL WIN_FUNC ResetEvent(HANDLE hEvent);
HANDLE WIN_FUNC CreateSemaphoreA(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,
							 LPCSTR lpName);
HANDLE WIN_FUNC CreateSemaphoreW(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount,
							 LPCWSTR lpName);
BOOL WIN_FUNC ReleaseSemaphore(HANDLE hSemaphore, LONG lReleaseCount, PLONG lpPreviousCount);
DWORD WIN_FUNC WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);

} // namespace kernel32
