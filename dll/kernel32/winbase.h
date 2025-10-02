#pragma once

#include "common.h"

#include <cstdarg>

namespace kernel32 {

BOOL WIN_FUNC IsBadReadPtr(LPCVOID lp, UINT_PTR ucb);
BOOL WIN_FUNC IsBadWritePtr(LPVOID lp, UINT_PTR ucb);
UINT WIN_FUNC SetHandleCount(UINT uNumber);
DWORD WIN_FUNC FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer,
							  DWORD nSize, va_list *Arguments);
PVOID WIN_FUNC EncodePointer(PVOID Ptr);
PVOID WIN_FUNC DecodePointer(PVOID Ptr);
BOOL WIN_FUNC SetDllDirectoryA(LPCSTR lpPathName);

BOOL WIN_FUNC GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize);
BOOL WIN_FUNC GetComputerNameW(LPWSTR lpBuffer, LPDWORD nSize);

HGLOBAL WIN_FUNC GlobalAlloc(UINT uFlags, SIZE_T dwBytes);
HGLOBAL WIN_FUNC GlobalFree(HGLOBAL hMem);
HGLOBAL WIN_FUNC GlobalReAlloc(HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags);
UINT WIN_FUNC GlobalFlags(HGLOBAL hMem);

HLOCAL WIN_FUNC LocalAlloc(UINT uFlags, SIZE_T uBytes);
HLOCAL WIN_FUNC LocalFree(HLOCAL hMem);
HLOCAL WIN_FUNC LocalReAlloc(HLOCAL hMem, SIZE_T uBytes, UINT uFlags);
HLOCAL WIN_FUNC LocalHandle(LPCVOID pMem);
LPVOID WIN_FUNC LocalLock(HLOCAL hMem);
BOOL WIN_FUNC LocalUnlock(HLOCAL hMem);
SIZE_T WIN_FUNC LocalSize(HLOCAL hMem);
UINT WIN_FUNC LocalFlags(HLOCAL hMem);

UINT WIN_FUNC GetSystemDirectoryA(LPSTR lpBuffer, UINT uSize);
UINT WIN_FUNC GetSystemDirectoryW(LPWSTR lpBuffer, UINT uSize);
UINT WIN_FUNC GetSystemWow64DirectoryA(LPSTR lpBuffer, UINT uSize);
UINT WIN_FUNC GetSystemWow64DirectoryW(LPWSTR lpBuffer, UINT uSize);
UINT WIN_FUNC GetWindowsDirectoryA(LPSTR lpBuffer, UINT uSize);
DWORD WIN_FUNC GetCurrentDirectoryA(DWORD nBufferLength, LPSTR lpBuffer);
DWORD WIN_FUNC GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer);
int WIN_FUNC SetCurrentDirectoryA(LPCSTR lpPathName);
int WIN_FUNC SetCurrentDirectoryW(LPCWSTR lpPathName);
DWORD WIN_FUNC GetLongPathNameA(LPCSTR lpszShortPath, LPSTR lpszLongPath, DWORD cchBuffer);
DWORD WIN_FUNC GetLongPathNameW(LPCWSTR lpszShortPath, LPWSTR lpszLongPath, DWORD cchBuffer);
BOOL WIN_FUNC GetDiskFreeSpaceA(LPCSTR lpRootPathName, LPDWORD lpSectorsPerCluster, LPDWORD lpBytesPerSector,
								LPDWORD lpNumberOfFreeClusters, LPDWORD lpTotalNumberOfClusters);
BOOL WIN_FUNC GetDiskFreeSpaceW(LPCWSTR lpRootPathName, LPDWORD lpSectorsPerCluster, LPDWORD lpBytesPerSector,
								LPDWORD lpNumberOfFreeClusters, LPDWORD lpTotalNumberOfClusters);
BOOL WIN_FUNC GetDiskFreeSpaceExA(LPCSTR lpDirectoryName, uint64_t *lpFreeBytesAvailableToCaller,
								  uint64_t *lpTotalNumberOfBytes, uint64_t *lpTotalNumberOfFreeBytes);
BOOL WIN_FUNC GetDiskFreeSpaceExW(LPCWSTR lpDirectoryName, uint64_t *lpFreeBytesAvailableToCaller,
								  uint64_t *lpTotalNumberOfBytes, uint64_t *lpTotalNumberOfFreeBytes);

} // namespace kernel32
