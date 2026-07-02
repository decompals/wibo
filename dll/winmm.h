#pragma once

#include "types.h"

using MMRESULT = UINT;

struct TIMECAPS {
	UINT wPeriodMin;
	UINT wPeriodMax;
};

using LPTIMECAPS = TIMECAPS *;

namespace winmm {

DWORD WINAPI timeGetTime();
MMRESULT WINAPI timeGetDevCaps(LPTIMECAPS ptc, UINT cbtc);

} // namespace winmm
