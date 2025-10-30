#pragma once

#include "types.h"

namespace kernel32 {

BOOL WINAPI CloseHandle(HANDLE hObject);
BOOL WINAPI DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle,
							  LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);

} // namespace kernel32
