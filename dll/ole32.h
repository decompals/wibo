#pragma once

#include "types.h"

namespace ole32 {

HRESULT WINAPI CoInitialize(LPVOID pvReserved);
HRESULT WINAPI CoCreateInstance(const GUID *rclsid, LPVOID pUnkOuter, DWORD dwClsContext, const GUID *riid, GUEST_PTR *ppv);
HRESULT WINAPI CLSIDFromString(LPCWSTR lpsz, GUID *pclsid);

} // namespace ole32
