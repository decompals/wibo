#pragma once

#include "common.h"

namespace kernel32 {

LPSTR WIN_FUNC GetCommandLineA();
LPWSTR WIN_FUNC GetCommandLineW();
HANDLE WIN_FUNC GetStdHandle(DWORD nStdHandle);
BOOL WIN_FUNC SetStdHandle(DWORD nStdHandle, HANDLE hHandle);
LPCH WIN_FUNC GetEnvironmentStrings();
LPWCH WIN_FUNC GetEnvironmentStringsW();
BOOL WIN_FUNC FreeEnvironmentStringsA(LPCH penv);
BOOL WIN_FUNC FreeEnvironmentStringsW(LPWCH penv);
DWORD WIN_FUNC GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize);
DWORD WIN_FUNC GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize);
BOOL WIN_FUNC SetEnvironmentVariableA(LPCSTR lpName, LPCSTR lpValue);
BOOL WIN_FUNC SetEnvironmentVariableW(LPCWSTR lpName, LPCWSTR lpValue);

} // namespace kernel32
