#pragma once

#include "common.h"
#include "minwinbase.h"

// Allocation type flags
constexpr DWORD MEM_COMMIT = 0x00001000;
constexpr DWORD MEM_RESERVE = 0x00002000;
constexpr DWORD MEM_DECOMMIT = 0x00004000;
constexpr DWORD MEM_RELEASE = 0x00008000;
constexpr DWORD MEM_RESET = 0x00080000;
constexpr DWORD MEM_RESET_UNDO = 0x01000000;
constexpr DWORD MEM_TOP_DOWN = 0x00100000;
constexpr DWORD MEM_WRITE_WATCH = 0x00200000;
constexpr DWORD MEM_PHYSICAL = 0x00400000;
constexpr DWORD MEM_PRIVATE = 0x00020000;
constexpr DWORD MEM_LARGE_PAGES = 0x20000000;
constexpr DWORD MEM_COALESCE_PLACEHOLDERS = 0x00000001;
constexpr DWORD MEM_PRESERVE_PLACEHOLDER = 0x00000002;

// Page protection constants
constexpr DWORD PAGE_NOACCESS = 0x01;
constexpr DWORD PAGE_READONLY = 0x02;
constexpr DWORD PAGE_READWRITE = 0x04;
constexpr DWORD PAGE_WRITECOPY = 0x08;
constexpr DWORD PAGE_EXECUTE = 0x10;
constexpr DWORD PAGE_EXECUTE_READ = 0x20;
constexpr DWORD PAGE_EXECUTE_READWRITE = 0x40;
constexpr DWORD PAGE_EXECUTE_WRITECOPY = 0x80;

constexpr DWORD FILE_MAP_COPY = 0x00000001;
constexpr DWORD FILE_MAP_WRITE = 0x00000002;
constexpr DWORD FILE_MAP_READ = 0x00000004;
constexpr DWORD FILE_MAP_EXECUTE = 0x00000020;

struct MEMORY_BASIC_INFORMATION {
	PVOID BaseAddress;
	PVOID AllocationBase;
	DWORD AllocationProtect;
	SIZE_T RegionSize;
	DWORD State;
	DWORD Protect;
	DWORD Type;
};

using PMEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION *;

namespace kernel32 {

HANDLE WIN_FUNC CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect,
								   DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
HANDLE WIN_FUNC CreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect,
								   DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName);
LPVOID WIN_FUNC MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh,
							  DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
BOOL WIN_FUNC UnmapViewOfFile(LPCVOID lpBaseAddress);

LPVOID WIN_FUNC VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL WIN_FUNC VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
BOOL WIN_FUNC VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
SIZE_T WIN_FUNC VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
BOOL WIN_FUNC GetProcessWorkingSetSize(HANDLE hProcess, PSIZE_T lpMinimumWorkingSetSize,
									   PSIZE_T lpMaximumWorkingSetSize);
BOOL WIN_FUNC SetProcessWorkingSetSize(HANDLE hProcess, SIZE_T dwMinimumWorkingSetSize, SIZE_T dwMaximumWorkingSetSize);

} // namespace kernel32
