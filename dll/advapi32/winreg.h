#pragma once

#include "types.h"

struct FILETIME;

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

constexpr DWORD REG_CREATED_NEW_KEY = 0x00000001;
constexpr DWORD REG_OPENED_EXISTING_KEY = 0x00000002;

constexpr REGSAM KEY_WOW64_64KEY = 0x00000100;
constexpr REGSAM KEY_WOW64_32KEY = 0x00000200;

namespace advapi32 {

LSTATUS WINAPI RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions,
							   REGSAM samDesired, void *lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);
LSTATUS WINAPI RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions,
							   REGSAM samDesired, void *lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);
LSTATUS WINAPI RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
LSTATUS WINAPI RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
LSTATUS WINAPI RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, BYTE *lpData,
								LPDWORD lpcbData);
LSTATUS WINAPI RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, BYTE *lpData,
								LPDWORD lpcbData);
LSTATUS WINAPI RegEnumKeyExA(HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved,
							 LPSTR lpClass, LPDWORD lpcchClass, FILETIME *lpftLastWriteTime);
LSTATUS WINAPI RegEnumKeyExW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved,
							 LPWSTR lpClass, LPDWORD lpcchClass, FILETIME *lpftLastWriteTime);
LSTATUS WINAPI RegCloseKey(HKEY hKey);

} // namespace advapi32
