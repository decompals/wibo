#pragma once

#include "common.h"
#include "minwinbase.h"

namespace kernel32 {

BOOL WIN_FUNC CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize);
HANDLE WIN_FUNC CreateNamedPipeA(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances,
								 DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut,
								 LPSECURITY_ATTRIBUTES lpSecurityAttributes);
BOOL WIN_FUNC ConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped);
bool tryCreateFileNamedPipeA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
							 LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
							 DWORD dwFlagsAndAttributes, HANDLE &outHandle);

} // namespace kernel32
