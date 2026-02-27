#pragma once

#include "types.h"

namespace lmgr {

int CDECL lc_checkout();
int CDECL lc_set_attr();
int CDECL lc_new_job();
int CDECL lc_free_job();
int CDECL lc_checkin();

int CDECL lp_checkout(int a, int b, LPCSTR c, LPCSTR d, int e, LPCSTR f, int *out);
int CDECL lp_checkin();

} // namespace lmgr
