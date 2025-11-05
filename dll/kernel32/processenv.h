#pragma once

#include "types.h"

namespace kernel32 {

GUEST_PTR WINAPI GetCommandLineA();
GUEST_PTR WINAPI GetCommandLineW();
HANDLE WINAPI GetStdHandle(DWORD nStdHandle);
BOOL WINAPI SetStdHandle(DWORD nStdHandle, HANDLE hHandle);
GUEST_PTR WINAPI GetEnvironmentStrings();
GUEST_PTR WINAPI GetEnvironmentStringsA();
GUEST_PTR WINAPI GetEnvironmentStringsW();
BOOL WINAPI FreeEnvironmentStringsA(LPCH penv);
BOOL WINAPI FreeEnvironmentStringsW(LPWCH penv);
DWORD WINAPI GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize);
DWORD WINAPI GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize);
BOOL WINAPI SetEnvironmentVariableA(LPCSTR lpName, LPCSTR lpValue);
BOOL WINAPI SetEnvironmentVariableW(LPCWSTR lpName, LPCWSTR lpValue);

} // namespace kernel32
