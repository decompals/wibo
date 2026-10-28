#pragma once

#include "types.h"

using OLECHAR = WCHAR;
using BSTR = OLECHAR *;

namespace oleaut32 {

BSTR WINAPI SysAllocStringLen(const OLECHAR *strIn, UINT ui);
void WINAPI SysFreeString(BSTR bstrString);

} // namespace oleaut32
