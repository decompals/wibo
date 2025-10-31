#pragma once

#include "types.h"

namespace lmgr {

int CDECL lp_checkout(int a, int b, LPCSTR c, LPCSTR d, int e, LPCSTR f, int *out);
int CDECL lp_checkin();

} // namespace lmgr
