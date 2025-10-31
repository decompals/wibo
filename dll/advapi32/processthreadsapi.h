#pragma once

#include "types.h"

namespace advapi32 {

BOOL WINAPI OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);

} // namespace advapi32
