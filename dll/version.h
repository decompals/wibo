#pragma once

#include "types.h"

namespace version {

UINT WINAPI GetFileVersionInfoSizeA(LPCSTR lptstrFilename, LPDWORD lpdwHandle);
UINT WINAPI GetFileVersionInfoA(LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
UINT WINAPI VerQueryValueA(LPCVOID pBlock, LPCSTR lpSubBlock, GUEST_PTR *lplpBuffer, PUINT puLen);
UINT WINAPI GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle);
UINT WINAPI GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData);
UINT WINAPI VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock, GUEST_PTR *lplpBuffer, PUINT puLen);

} // namespace version
