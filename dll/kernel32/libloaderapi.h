#pragma once

#include "common.h"

namespace kernel32 {

BOOL WIN_FUNC DisableThreadLibraryCalls(HMODULE hLibModule);
HMODULE WIN_FUNC GetModuleHandleA(LPCSTR lpModuleName);
HMODULE WIN_FUNC GetModuleHandleW(LPCWSTR lpModuleName);
DWORD WIN_FUNC GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize);
DWORD WIN_FUNC GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
HRSRC WIN_FUNC FindResourceA(HMODULE hModule, LPCSTR lpName, LPCSTR lpType);
HRSRC WIN_FUNC FindResourceExA(HMODULE hModule, LPCSTR lpType, LPCSTR lpName, WORD wLanguage);
HRSRC WIN_FUNC FindResourceW(HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType);
HRSRC WIN_FUNC FindResourceExW(HMODULE hModule, LPCWSTR lpType, LPCWSTR lpName, WORD wLanguage);
HGLOBAL WIN_FUNC LoadResource(HMODULE hModule, HRSRC hResInfo);
LPVOID WIN_FUNC LockResource(HGLOBAL hResData);
DWORD WIN_FUNC SizeofResource(HMODULE hModule, HRSRC hResInfo);
HMODULE WIN_FUNC LoadLibraryA(LPCSTR lpLibFileName);
HMODULE WIN_FUNC LoadLibraryW(LPCWSTR lpLibFileName);
HMODULE WIN_FUNC LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
BOOL WIN_FUNC FreeLibrary(HMODULE hLibModule);
FARPROC WIN_FUNC GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

} // namespace kernel32
