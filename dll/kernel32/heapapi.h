#pragma once

#include "types.h"

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

HANDLE WINAPI HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);
BOOL WINAPI HeapDestroy(HANDLE hHeap);
HANDLE WINAPI GetProcessHeap();
BOOL WINAPI HeapSetInformation(HANDLE HeapHandle, HEAP_INFORMATION_CLASS HeapInformationClass, PVOID HeapInformation,
								 SIZE_T HeapInformationLength);
LPVOID WINAPI HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
LPVOID WINAPI HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
SIZE_T WINAPI HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem);
BOOL WINAPI HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);

} // namespace kernel32
