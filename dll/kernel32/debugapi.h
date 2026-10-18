#pragma once

#include "types.h"

namespace kernel32 {

BOOL WINAPI IsDebuggerPresent();
void WINAPI OutputDebugStringA(LPCSTR lpOutputString);

} // namespace kernel32
