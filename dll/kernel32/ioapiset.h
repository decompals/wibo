#pragma once

#include "common.h"
#include "minwinbase.h"

namespace kernel32 {

BOOL WIN_FUNC GetOverlappedResult(HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred,
								  BOOL bWait);

} // namespace kernel32
