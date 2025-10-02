#pragma once

#include "common.h"

constexpr DWORD HEAP_NO_SERIALIZE = 0x00000001;
constexpr DWORD HEAP_GENERATE_EXCEPTIONS = 0x00000004;
constexpr DWORD HEAP_ZERO_MEMORY = 0x00000008;
constexpr DWORD HEAP_REALLOC_IN_PLACE_ONLY = 0x00000010;
constexpr DWORD HEAP_CREATE_ENABLE_EXECUTE = 0x00040000;

enum HEAP_INFORMATION_CLASS {
	HeapCompatibilityInformation = 0,
	HeapEnableTerminationOnCorruption = 1,
	HeapOptimizeResources = 3,
};

namespace kernel32 {

HANDLE WIN_FUNC HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);
BOOL WIN_FUNC HeapDestroy(HANDLE hHeap);
HANDLE WIN_FUNC GetProcessHeap();
BOOL WIN_FUNC HeapSetInformation(HANDLE HeapHandle, HEAP_INFORMATION_CLASS HeapInformationClass, PVOID HeapInformation,
								 SIZE_T HeapInformationLength);
LPVOID WIN_FUNC HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
LPVOID WIN_FUNC HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
SIZE_T WIN_FUNC HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem);
BOOL WIN_FUNC HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);

} // namespace kernel32
