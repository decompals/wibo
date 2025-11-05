#pragma once

#include "types.h"

struct GUID;

struct ACTCTX_SECTION_KEYED_DATA_ASSEMBLY_METADATA {
	GUEST_PTR lpInformation;
	GUEST_PTR lpSectionBase;
	ULONG ulSectionLength;
	GUEST_PTR lpSectionGlobalData;
	ULONG ulSectionGlobalDataLength;
};

struct ACTCTX_SECTION_KEYED_DATA {
	ULONG cbSize;
	ULONG ulDataFormatVersion;
	GUEST_PTR lpData;
	ULONG ulLength;
	GUEST_PTR lpSectionGlobalData;
	ULONG ulSectionGlobalDataLength;
	GUEST_PTR lpSectionBase;
	ULONG ulSectionTotalLength;
	HANDLE hActCtx;
	ULONG ulAssemblyRosterIndex;
	ULONG ulFlags;
	ACTCTX_SECTION_KEYED_DATA_ASSEMBLY_METADATA AssemblyMetadata;
};

using PACTCTX_SECTION_KEYED_DATA = ACTCTX_SECTION_KEYED_DATA *;
using PCACTCTX_SECTION_KEYED_DATA = const ACTCTX_SECTION_KEYED_DATA *;

constexpr DWORD FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX = 0x00000001;

constexpr ULONG ACTIVATION_CONTEXT_SECTION_ASSEMBLY_INFORMATION = 1;
constexpr ULONG ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION = 2;
constexpr ULONG ACTIVATION_CONTEXT_SECTION_WINDOW_CLASS_REDIRECTION = 3;
constexpr ULONG ACTIVATION_CONTEXT_SECTION_COM_PROGID_REDIRECTION = 7;

constexpr ULONG ACTCTX_SECTION_KEYED_DATA_FLAG_FOUND_IN_ACTCTX = 0x00000001;

constexpr ULONG ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_INCLUDES_BASE_NAME = 1;
constexpr ULONG ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_OMITS_ASSEMBLY_ROOT = 2;
constexpr ULONG ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_EXPAND = 4;
constexpr ULONG ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SYSTEM_DEFAULT_REDIRECTED_SYSTEM32_DLL = 8;

struct ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION {
	ULONG Size;
	ULONG Flags;
	ULONG TotalPathLength;
	ULONG PathSegmentCount;
	ULONG PathSegmentOffset;
};

struct ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_SEGMENT {
	ULONG Length;
	ULONG Offset;
};

namespace kernel32 {

BOOL WINAPI IsBadReadPtr(LPCVOID lp, UINT_PTR ucb);
BOOL WINAPI IsBadWritePtr(LPVOID lp, UINT_PTR ucb);
ATOM WINAPI FindAtomA(LPCSTR lpString);
ATOM WINAPI FindAtomW(LPCWSTR lpString);
ATOM WINAPI AddAtomA(LPCSTR lpString);
ATOM WINAPI AddAtomW(LPCWSTR lpString);
UINT WINAPI GetAtomNameA(ATOM nAtom, LPSTR lpBuffer, int nSize);
UINT WINAPI GetAtomNameW(ATOM nAtom, LPWSTR lpBuffer, int nSize);
UINT WINAPI SetHandleCount(UINT uNumber);
// DWORD WINAPI FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer,
// 							DWORD nSize, va_list *Arguments);
PVOID WINAPI EncodePointer(PVOID Ptr);
PVOID WINAPI DecodePointer(PVOID Ptr);
BOOL WINAPI SetDllDirectoryA(LPCSTR lpPathName);

BOOL WINAPI FindActCtxSectionStringA(DWORD dwFlags, const GUID *lpExtensionGuid, ULONG ulSectionId,
									 LPCSTR lpStringToFind, PACTCTX_SECTION_KEYED_DATA ReturnedData);
BOOL WINAPI FindActCtxSectionStringW(DWORD dwFlags, const GUID *lpExtensionGuid, ULONG ulSectionId,
									 LPCWSTR lpStringToFind, PACTCTX_SECTION_KEYED_DATA ReturnedData);

BOOL WINAPI GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize);
BOOL WINAPI GetComputerNameW(LPWSTR lpBuffer, LPDWORD nSize);

HGLOBAL WINAPI GlobalAlloc(UINT uFlags, SIZE_T dwBytes);
HGLOBAL WINAPI GlobalFree(HGLOBAL hMem);
HGLOBAL WINAPI GlobalReAlloc(HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags);
UINT WINAPI GlobalFlags(HGLOBAL hMem);

HLOCAL WINAPI LocalAlloc(UINT uFlags, SIZE_T uBytes);
HLOCAL WINAPI LocalFree(HLOCAL hMem);
HLOCAL WINAPI LocalReAlloc(HLOCAL hMem, SIZE_T uBytes, UINT uFlags);
HLOCAL WINAPI LocalHandle(LPCVOID pMem);
LPVOID WINAPI LocalLock(HLOCAL hMem);
BOOL WINAPI LocalUnlock(HLOCAL hMem);
SIZE_T WINAPI LocalSize(HLOCAL hMem);
UINT WINAPI LocalFlags(HLOCAL hMem);

UINT WINAPI GetSystemDirectoryA(LPSTR lpBuffer, UINT uSize);
UINT WINAPI GetSystemDirectoryW(LPWSTR lpBuffer, UINT uSize);
UINT WINAPI GetSystemWow64DirectoryA(LPSTR lpBuffer, UINT uSize);
UINT WINAPI GetSystemWow64DirectoryW(LPWSTR lpBuffer, UINT uSize);
UINT WINAPI GetWindowsDirectoryA(LPSTR lpBuffer, UINT uSize);
UINT WINAPI GetSystemWindowsDirectoryA(LPSTR lpBuffer, UINT uSize);
UINT WINAPI GetSystemWindowsDirectoryW(LPWSTR lpBuffer, UINT uSize);
DWORD WINAPI GetCurrentDirectoryA(DWORD nBufferLength, LPSTR lpBuffer);
DWORD WINAPI GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer);
int WINAPI SetCurrentDirectoryA(LPCSTR lpPathName);
int WINAPI SetCurrentDirectoryW(LPCWSTR lpPathName);
DWORD WINAPI GetLongPathNameA(LPCSTR lpszShortPath, LPSTR lpszLongPath, DWORD cchBuffer);
DWORD WINAPI GetLongPathNameW(LPCWSTR lpszShortPath, LPWSTR lpszLongPath, DWORD cchBuffer);
BOOL WINAPI GetDiskFreeSpaceA(LPCSTR lpRootPathName, LPDWORD lpSectorsPerCluster, LPDWORD lpBytesPerSector,
							  LPDWORD lpNumberOfFreeClusters, LPDWORD lpTotalNumberOfClusters);
BOOL WINAPI GetDiskFreeSpaceW(LPCWSTR lpRootPathName, LPDWORD lpSectorsPerCluster, LPDWORD lpBytesPerSector,
							  LPDWORD lpNumberOfFreeClusters, LPDWORD lpTotalNumberOfClusters);
BOOL WINAPI GetDiskFreeSpaceExA(LPCSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller,
								PULARGE_INTEGER lpTotalNumberOfBytes, PULARGE_INTEGER lpTotalNumberOfFreeBytes);
BOOL WINAPI GetDiskFreeSpaceExW(LPCWSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller,
								PULARGE_INTEGER lpTotalNumberOfBytes, PULARGE_INTEGER lpTotalNumberOfFreeBytes);

} // namespace kernel32
