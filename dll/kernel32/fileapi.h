#pragma once

#include "types.h"
#include "minwinbase.h"

struct BY_HANDLE_FILE_INFORMATION {
	DWORD dwFileAttributes;
	FILETIME ftCreationTime;
	FILETIME ftLastAccessTime;
	FILETIME ftLastWriteTime;
	DWORD dwVolumeSerialNumber;
	DWORD nFileSizeHigh;
	DWORD nFileSizeLow;
	DWORD nNumberOfLinks;
	DWORD nFileIndexHigh;
	DWORD nFileIndexLow;
};

using PBY_HANDLE_FILE_INFORMATION = BY_HANDLE_FILE_INFORMATION *;
using LPBY_HANDLE_FILE_INFORMATION = BY_HANDLE_FILE_INFORMATION *;

constexpr DWORD CREATE_NEW = 1;
constexpr DWORD CREATE_ALWAYS = 2;
constexpr DWORD OPEN_EXISTING = 3;
constexpr DWORD OPEN_ALWAYS = 4;
constexpr DWORD TRUNCATE_EXISTING = 5;

constexpr DWORD FILE_BEGIN = 0;
constexpr DWORD FILE_CURRENT = 1;
constexpr DWORD FILE_END = 2;

constexpr DWORD FILE_ATTRIBUTE_READONLY = 0x00000001;
constexpr DWORD FILE_ATTRIBUTE_HIDDEN = 0x00000002;
constexpr DWORD FILE_ATTRIBUTE_SYSTEM = 0x00000004;
constexpr DWORD FILE_ATTRIBUTE_ARCHIVE = 0x00000020;
constexpr DWORD FILE_ATTRIBUTE_TEMPORARY = 0x00000100;
constexpr DWORD FILE_ATTRIBUTE_OFFLINE = 0x00001000;
constexpr DWORD FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000;
constexpr DWORD FILE_ATTRIBUTE_ENCRYPTED = 0x00004000;

constexpr UINT DRIVE_UNKNOWN = 0;
constexpr UINT DRIVE_NO_ROOT_DIR = 1;
constexpr UINT DRIVE_REMOVABLE = 2;
constexpr UINT DRIVE_FIXED = 3;
constexpr UINT DRIVE_REMOTE = 4;
constexpr UINT DRIVE_CDROM = 5;
constexpr UINT DRIVE_RAMDISK = 6;

constexpr DWORD FILE_TYPE_UNKNOWN = 0x0000;
constexpr DWORD FILE_TYPE_DISK = 0x0001;
constexpr DWORD FILE_TYPE_CHAR = 0x0002;
constexpr DWORD FILE_TYPE_PIPE = 0x0003;

constexpr DWORD INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF;
constexpr DWORD INVALID_FILE_SIZE = 0xFFFFFFFF;

namespace kernel32 {

DWORD WINAPI GetFullPathNameA(LPCSTR lpFileName, DWORD nBufferLength, LPSTR lpBuffer, GUEST_PTR *lpFilePart);
DWORD WINAPI GetFullPathNameW(LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, GUEST_PTR *lpFilePart);
DWORD WINAPI GetShortPathNameA(LPCSTR lpszLongPath, LPSTR lpszShortPath, DWORD cchBuffer);
DWORD WINAPI GetShortPathNameW(LPCWSTR lpszLongPath, LPWSTR lpszShortPath, DWORD cchBuffer);
UINT WINAPI GetTempFileNameA(LPCSTR lpPathName, LPCSTR lpPrefixString, UINT uUnique, LPSTR lpTempFileName);
DWORD WINAPI GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer);
HANDLE WINAPI FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
HANDLE WINAPI FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
HANDLE WINAPI FindFirstFileExA(LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData,
								 FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags);
BOOL WINAPI FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
BOOL WINAPI FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
BOOL WINAPI FindClose(HANDLE hFindFile);
DWORD WINAPI GetFileAttributesA(LPCSTR lpFileName);
DWORD WINAPI GetFileAttributesW(LPCWSTR lpFileName);
UINT WINAPI GetDriveTypeA(LPCSTR lpRootPathName);
UINT WINAPI GetDriveTypeW(LPCWSTR lpRootPathName);
BOOL WINAPI WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten,
						LPOVERLAPPED lpOverlapped);
BOOL WINAPI ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead,
					   LPOVERLAPPED lpOverlapped);
BOOL WINAPI FlushFileBuffers(HANDLE hFile);
HANDLE WINAPI CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
							LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
							DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
HANDLE WINAPI CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
							LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
							DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL WINAPI DeleteFileA(LPCSTR lpFileName);
BOOL WINAPI DeleteFileW(LPCWSTR lpFileName);
BOOL WINAPI MoveFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName);
BOOL WINAPI MoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName);
DWORD WINAPI SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
BOOL WINAPI SetFilePointerEx(HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpNewFilePointer,
							   DWORD dwMoveMethod);
BOOL WINAPI SetEndOfFile(HANDLE hFile);
BOOL WINAPI CreateDirectoryA(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
BOOL WINAPI RemoveDirectoryA(LPCSTR lpPathName);
BOOL WINAPI SetFileAttributesA(LPCSTR lpFileName, DWORD dwFileAttributes);
DWORD WINAPI GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);
BOOL WINAPI GetFileTime(HANDLE hFile, LPFILETIME lpCreationTime, LPFILETIME lpLastAccessTime,
						  LPFILETIME lpLastWriteTime);
BOOL WINAPI SetFileTime(HANDLE hFile, const FILETIME *lpCreationTime, const FILETIME *lpLastAccessTime,
						  const FILETIME *lpLastWriteTime);
BOOL WINAPI GetFileInformationByHandle(HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation);
DWORD WINAPI GetFileType(HANDLE hFile);
LONG WINAPI CompareFileTime(const FILETIME *lpFileTime1, const FILETIME *lpFileTime2);
BOOL WINAPI GetVolumeInformationA(LPCSTR lpRootPathName, LPSTR lpVolumeNameBuffer, DWORD nVolumeNameSize,
									LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength,
									LPDWORD lpFileSystemFlags, LPSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize);
BOOL WINAPI GetVolumeInformationW(LPCWSTR lpRootPathName, LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize,
									LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength,
									LPDWORD lpFileSystemFlags, LPWSTR lpFileSystemNameBuffer,
									DWORD nFileSystemNameSize);

} // namespace kernel32
