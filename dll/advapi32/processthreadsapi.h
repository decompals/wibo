#pragma once

#include "common.h"

namespace advapi32 {

BOOL WIN_FUNC OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);

} // namespace advapi32
