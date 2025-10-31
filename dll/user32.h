#pragma once

#include "types.h"

namespace user32 {

int WINAPI LoadStringA(HMODULE hInstance, UINT uID, LPSTR lpBuffer, int cchBufferMax);
int WINAPI LoadStringW(HMODULE hInstance, UINT uID, LPWSTR lpBuffer, int cchBufferMax);
int WINAPI MessageBoxA(HWND hwnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
HKL WINAPI GetKeyboardLayout(DWORD idThread);
HWINSTA WINAPI GetProcessWindowStation();
BOOL WINAPI GetUserObjectInformationA(HANDLE hObj, int nIndex, PVOID pvInfo, DWORD nLength, LPDWORD lpnLengthNeeded);
HWND WINAPI GetActiveWindow();

} // namespace user32
