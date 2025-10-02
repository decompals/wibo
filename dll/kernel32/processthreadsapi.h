#pragma once

#include "common.h"
#include "errors.h"
#include "minwinbase.h"

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

constexpr DWORD TLS_OUT_OF_INDEXES = 0xFFFFFFFFu;

typedef DWORD(WIN_FUNC *LPTHREAD_START_ROUTINE)(LPVOID);

namespace kernel32 {

HANDLE WIN_FUNC GetCurrentProcess();
DWORD WIN_FUNC GetCurrentProcessId();
DWORD WIN_FUNC GetCurrentThreadId();
HANDLE WIN_FUNC GetCurrentThread();
BOOL WIN_FUNC GetProcessAffinityMask(HANDLE hProcess, PDWORD_PTR lpProcessAffinityMask,
									 PDWORD_PTR lpSystemAffinityMask);
BOOL WIN_FUNC SetProcessAffinityMask(HANDLE hProcess, DWORD_PTR dwProcessAffinityMask);
DWORD_PTR WIN_FUNC SetThreadAffinityMask(HANDLE hThread, DWORD_PTR dwThreadAffinityMask);
DWORD WIN_FUNC ResumeThread(HANDLE hThread);
HRESULT WIN_FUNC SetThreadDescription(HANDLE hThread, LPCWSTR lpThreadDescription);
void WIN_FUNC ExitProcess(UINT uExitCode);
BOOL WIN_FUNC TerminateProcess(HANDLE hProcess, UINT uExitCode);
BOOL WIN_FUNC GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode);
DWORD WIN_FUNC TlsAlloc();
BOOL WIN_FUNC TlsFree(DWORD dwTlsIndex);
LPVOID WIN_FUNC TlsGetValue(DWORD dwTlsIndex);
BOOL WIN_FUNC TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue);
HANDLE WIN_FUNC CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
							 LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags,
							 LPDWORD lpThreadId);
void WIN_FUNC ExitThread(DWORD dwExitCode);
BOOL WIN_FUNC GetExitCodeThread(HANDLE hThread, LPDWORD lpExitCode);
BOOL WIN_FUNC SetThreadPriority(HANDLE hThread, int nPriority);
int WIN_FUNC GetThreadPriority(HANDLE hThread);
BOOL WIN_FUNC GetThreadTimes(HANDLE hThread, FILETIME *lpCreationTime, FILETIME *lpExitTime, FILETIME *lpKernelTime,
							 FILETIME *lpUserTime);
BOOL WIN_FUNC CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
							 LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
							 LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
							 LPPROCESS_INFORMATION lpProcessInformation);
BOOL WIN_FUNC CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
							 LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
							 LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
							 LPPROCESS_INFORMATION lpProcessInformation);
void WIN_FUNC GetStartupInfoA(LPSTARTUPINFOA lpStartupInfo);
void WIN_FUNC GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo);
BOOL WIN_FUNC SetThreadStackGuarantee(PULONG StackSizeInBytes);

} // namespace kernel32
