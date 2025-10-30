#pragma once

#include "types.h"
#include "minwinbase.h"

namespace kernel32 {

BOOL WINAPI GetOverlappedResult(HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred,
								  BOOL bWait);

} // namespace kernel32
