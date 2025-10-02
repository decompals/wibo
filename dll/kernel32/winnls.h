#pragma once

#include "common.h"

constexpr UINT MAX_DEFAULTCHAR = 2;
constexpr UINT MAX_LEADBYTES = 12;

struct CPINFO {
	UINT MaxCharSize;
	BYTE DefaultChar[MAX_DEFAULTCHAR];
	BYTE LeadByte[MAX_LEADBYTES];
};

using LPCPINFO = CPINFO *;
using LOCALE_ENUMPROCA = BOOL(WIN_FUNC *)(LPSTR);

namespace kernel32 {

UINT WIN_FUNC GetACP();
LANGID WIN_FUNC GetSystemDefaultLangID();
LANGID WIN_FUNC GetUserDefaultUILanguage();
BOOL WIN_FUNC GetCPInfo(UINT CodePage, LPCPINFO lpCPInfo);
int WIN_FUNC CompareStringA(LCID Locale, DWORD dwCmpFlags, LPCSTR lpString1, int cchCount1, LPCSTR lpString2,
							int cchCount2);
int WIN_FUNC CompareStringW(LCID Locale, DWORD dwCmpFlags, LPCWCH lpString1, int cchCount1, LPCWCH lpString2,
							int cchCount2);
BOOL WIN_FUNC IsValidCodePage(UINT CodePage);
BOOL WIN_FUNC IsValidLocale(LCID Locale, DWORD dwFlags);
int WIN_FUNC GetLocaleInfoA(LCID Locale, LCTYPE LCType, LPSTR lpLCData, int cchData);
int WIN_FUNC GetLocaleInfoW(LCID Locale, LCTYPE LCType, LPWSTR lpLCData, int cchData);
BOOL WIN_FUNC EnumSystemLocalesA(LOCALE_ENUMPROCA lpLocaleEnumProc, DWORD dwFlags);
LCID WIN_FUNC GetUserDefaultLCID();
BOOL WIN_FUNC IsDBCSLeadByte(BYTE TestChar);
BOOL WIN_FUNC IsDBCSLeadByteEx(UINT CodePage, BYTE TestChar);
int WIN_FUNC LCMapStringW(LCID Locale, DWORD dwMapFlags, LPCWCH lpSrcStr, int cchSrc, LPWSTR lpDestStr, int cchDest);
int WIN_FUNC LCMapStringA(LCID Locale, DWORD dwMapFlags, LPCCH lpSrcStr, int cchSrc, LPSTR lpDestStr, int cchDest);

} // namespace kernel32
