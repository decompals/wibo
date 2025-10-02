#pragma once

#include "common.h"

#ifndef HKEY_CLASSES_ROOT
#define HKEY_CLASSES_ROOT ((HKEY)(uintptr_t)0x80000000u)
#endif
#ifndef HKEY_CURRENT_USER
#define HKEY_CURRENT_USER ((HKEY)(uintptr_t)0x80000001u)
#endif
#ifndef HKEY_LOCAL_MACHINE
#define HKEY_LOCAL_MACHINE ((HKEY)(uintptr_t)0x80000002u)
#endif
#ifndef HKEY_USERS
#define HKEY_USERS ((HKEY)(uintptr_t)0x80000003u)
#endif
#ifndef HKEY_PERFORMANCE_DATA
#define HKEY_PERFORMANCE_DATA ((HKEY)(uintptr_t)0x80000004u)
#endif
#ifndef HKEY_CURRENT_CONFIG
#define HKEY_CURRENT_CONFIG ((HKEY)(uintptr_t)0x80000005u)
#endif

constexpr DWORD REG_OPTION_OPEN_LINK = 0x00000008;

constexpr REGSAM KEY_WOW64_64KEY = 0x00000100;
constexpr REGSAM KEY_WOW64_32KEY = 0x00000200;

namespace advapi32 {

LSTATUS WIN_FUNC RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
LSTATUS WIN_FUNC RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
LSTATUS WIN_FUNC RegCloseKey(HKEY hKey);

} // namespace advapi32
