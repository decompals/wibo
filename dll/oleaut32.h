#pragma once

#include "types.h"

namespace oleaut32 {

GUEST_PTR WINAPI SysAllocString(LPCWSTR psz);
void WINAPI SysFreeString(LPWSTR bstrString);
UINT WINAPI SysStringLen(LPCWSTR pbstr);

} // namespace oleaut32
