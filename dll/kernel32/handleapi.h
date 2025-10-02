#pragma once

#include "common.h"

namespace kernel32 {

BOOL WIN_FUNC CloseHandle(HANDLE hObject);
BOOL WIN_FUNC DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle,
							  LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);

} // namespace kernel32
