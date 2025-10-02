#pragma once

#include "common.h"
#include "minwinbase.h"

namespace kernel32 {

BOOL WIN_FUNC CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize);

} // namespace kernel32
