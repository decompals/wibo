#pragma once

#include "common.h"

namespace kernel32 {

BOOL WIN_FUNC QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
BOOL WIN_FUNC QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency);

} // namespace kernel32
