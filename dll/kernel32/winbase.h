#pragma once

#include "common.h"

#include <cstdarg>

struct GUID;

struct ACTCTX_SECTION_KEYED_DATA_ASSEMBLY_METADATA {
	PVOID lpInformation;
	PVOID lpSectionBase;
	ULONG ulSectionLength;
	PVOID lpSectionGlobalData;
	ULONG ulSectionGlobalDataLength;
};

struct ACTCTX_SECTION_KEYED_DATA {
	ULONG cbSize;
	ULONG ulDataFormatVersion;
	PVOID lpData;
	ULONG ulLength;
	PVOID lpSectionGlobalData;
	ULONG ulSectionGlobalDataLength;
	PVOID lpSectionBase;
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

BOOL WIN_FUNC IsBadReadPtr(LPCVOID lp, UINT_PTR ucb);
BOOL WIN_FUNC IsBadWritePtr(LPVOID lp, UINT_PTR ucb);
ATOM WIN_FUNC FindAtomA(LPCSTR lpString);
ATOM WIN_FUNC FindAtomW(LPCWSTR lpString);
ATOM WIN_FUNC AddAtomA(LPCSTR lpString);
ATOM WIN_FUNC AddAtomW(LPCWSTR lpString);
UINT WIN_FUNC GetAtomNameA(ATOM nAtom, LPSTR lpBuffer, int nSize);
UINT WIN_FUNC GetAtomNameW(ATOM nAtom, LPWSTR lpBuffer, int nSize);
UINT WIN_FUNC SetHandleCount(UINT uNumber);
DWORD WIN_FUNC FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer,
							  DWORD nSize, va_list *Arguments);
PVOID WIN_FUNC EncodePointer(PVOID Ptr);
PVOID WIN_FUNC DecodePointer(PVOID Ptr);
BOOL WIN_FUNC SetDllDirectoryA(LPCSTR lpPathName);

BOOL WIN_FUNC FindActCtxSectionStringA(DWORD dwFlags, const GUID *lpExtensionGuid, ULONG ulSectionId,
									   LPCSTR lpStringToFind, PACTCTX_SECTION_KEYED_DATA ReturnedData);
BOOL WIN_FUNC FindActCtxSectionStringW(DWORD dwFlags, const GUID *lpExtensionGuid, ULONG ulSectionId,
									   LPCWSTR lpStringToFind, PACTCTX_SECTION_KEYED_DATA ReturnedData);

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
UINT WIN_FUNC GetSystemWindowsDirectoryA(LPSTR lpBuffer, UINT uSize);
UINT WIN_FUNC GetSystemWindowsDirectoryW(LPWSTR lpBuffer, UINT uSize);
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
