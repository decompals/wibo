#pragma once

#include "common.h"
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

DWORD WIN_FUNC GetFullPathNameA(LPCSTR lpFileName, DWORD nBufferLength, LPSTR lpBuffer, LPSTR *lpFilePart);
DWORD WIN_FUNC GetFullPathNameW(LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart);
DWORD WIN_FUNC GetShortPathNameA(LPCSTR lpszLongPath, LPSTR lpszShortPath, DWORD cchBuffer);
DWORD WIN_FUNC GetShortPathNameW(LPCWSTR lpszLongPath, LPWSTR lpszShortPath, DWORD cchBuffer);
UINT WIN_FUNC GetTempFileNameA(LPCSTR lpPathName, LPCSTR lpPrefixString, UINT uUnique, LPSTR lpTempFileName);
DWORD WIN_FUNC GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer);
HANDLE WIN_FUNC FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
HANDLE WIN_FUNC FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
HANDLE WIN_FUNC FindFirstFileExA(LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData,
								 FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags);
BOOL WIN_FUNC FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
BOOL WIN_FUNC FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
BOOL WIN_FUNC FindClose(HANDLE hFindFile);
DWORD WIN_FUNC GetFileAttributesA(LPCSTR lpFileName);
DWORD WIN_FUNC GetFileAttributesW(LPCWSTR lpFileName);
UINT WIN_FUNC GetDriveTypeA(LPCSTR lpRootPathName);
UINT WIN_FUNC GetDriveTypeW(LPCWSTR lpRootPathName);
BOOL WIN_FUNC WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten,
						LPOVERLAPPED lpOverlapped);
BOOL WIN_FUNC ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead,
					   LPOVERLAPPED lpOverlapped);
BOOL WIN_FUNC FlushFileBuffers(HANDLE hFile);
HANDLE WIN_FUNC CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
							LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
							DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
HANDLE WIN_FUNC CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
							LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
							DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL WIN_FUNC DeleteFileA(LPCSTR lpFileName);
BOOL WIN_FUNC DeleteFileW(LPCWSTR lpFileName);
BOOL WIN_FUNC MoveFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName);
BOOL WIN_FUNC MoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName);
DWORD WIN_FUNC SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
BOOL WIN_FUNC SetFilePointerEx(HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpNewFilePointer,
							   DWORD dwMoveMethod);
BOOL WIN_FUNC SetEndOfFile(HANDLE hFile);
BOOL WIN_FUNC CreateDirectoryA(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
BOOL WIN_FUNC RemoveDirectoryA(LPCSTR lpPathName);
BOOL WIN_FUNC SetFileAttributesA(LPCSTR lpFileName, DWORD dwFileAttributes);
DWORD WIN_FUNC GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);
BOOL WIN_FUNC GetFileTime(HANDLE hFile, LPFILETIME lpCreationTime, LPFILETIME lpLastAccessTime,
						  LPFILETIME lpLastWriteTime);
BOOL WIN_FUNC SetFileTime(HANDLE hFile, const FILETIME *lpCreationTime, const FILETIME *lpLastAccessTime,
						  const FILETIME *lpLastWriteTime);
BOOL WIN_FUNC GetFileInformationByHandle(HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation);
DWORD WIN_FUNC GetFileType(HANDLE hFile);
LONG WIN_FUNC CompareFileTime(const FILETIME *lpFileTime1, const FILETIME *lpFileTime2);
BOOL WIN_FUNC GetVolumeInformationA(LPCSTR lpRootPathName, LPSTR lpVolumeNameBuffer, DWORD nVolumeNameSize,
									LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength,
									LPDWORD lpFileSystemFlags, LPSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize);
BOOL WIN_FUNC GetVolumeInformationW(LPCWSTR lpRootPathName, LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize,
									LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength,
									LPDWORD lpFileSystemFlags, LPWSTR lpFileSystemNameBuffer,
									DWORD nFileSystemNameSize);

} // namespace kernel32
