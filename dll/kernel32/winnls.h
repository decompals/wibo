#pragma once

#include "types.h"

using CALID = DWORD;
using CALTYPE = DWORD;

constexpr UINT MAX_DEFAULTCHAR = 2;
constexpr UINT MAX_LEADBYTES = 12;

struct CPINFO {
	UINT MaxCharSize;
	BYTE DefaultChar[MAX_DEFAULTCHAR];
	BYTE LeadByte[MAX_LEADBYTES];
};

using LPCPINFO = CPINFO *;
typedef BOOL(_CC_STDCALL *LOCALE_ENUMPROCA)(LPSTR);
typedef BOOL(_CC_STDCALL *CALINFO_ENUMPROCW)(LPWSTR);

namespace kernel32 {

UINT WINAPI GetACP();
LCID WINAPI GetThreadLocale();
BOOL WINAPI SetThreadLocale(LCID Locale);
LANGID WINAPI GetThreadUILanguage();
BOOL WINAPI GetThreadPreferredUILanguages(DWORD dwFlags, PULONG pulNumLanguages, LPWSTR pwszLanguagesBuffer,
										  PULONG pcchLanguagesBuffer);
BOOL WINAPI SetThreadPreferredUILanguages(DWORD dwFlags, LPCWSTR pwszLanguagesBuffer, PULONG pulNumLanguages);
int WINAPI CompareStringOrdinal(LPCWCH lpString1, int cchCount1, LPCWCH lpString2, int cchCount2, BOOL bIgnoreCase);
LANGID WINAPI GetSystemDefaultLangID();
LANGID WINAPI GetUserDefaultUILanguage();
int WINAPI GetUserDefaultLocaleName(LPWSTR lpLocaleName, int cchLocaleName);
LCID WINAPI LocaleNameToLCID(LPCWSTR lpName, DWORD dwFlags);
BOOL WINAPI GetCPInfo(UINT CodePage, LPCPINFO lpCPInfo);
int WINAPI CompareStringA(LCID Locale, DWORD dwCmpFlags, LPCSTR lpString1, int cchCount1, LPCSTR lpString2,
						  int cchCount2);
int WINAPI CompareStringW(LCID Locale, DWORD dwCmpFlags, LPCWCH lpString1, int cchCount1, LPCWCH lpString2,
						  int cchCount2);
BOOL WINAPI IsValidCodePage(UINT CodePage);
BOOL WINAPI IsValidLocale(LCID Locale, DWORD dwFlags);
int WINAPI GetLocaleInfoA(LCID Locale, LCTYPE LCType, LPSTR lpLCData, int cchData);
int WINAPI GetLocaleInfoW(LCID Locale, LCTYPE LCType, LPWSTR lpLCData, int cchData);
int WINAPI GetLocaleInfoEx(LPCWSTR lpLocaleName, LCTYPE LCType, LPWSTR lpLCData, int cchData);
BOOL WINAPI EnumSystemLocalesA(LOCALE_ENUMPROCA lpLocaleEnumProc, DWORD dwFlags);
BOOL WINAPI EnumCalendarInfoW(CALINFO_ENUMPROCW lpCalInfoEnumProc, LCID Locale, CALID Calendar, CALTYPE CalType);
LCID WINAPI GetUserDefaultLCID();
BOOL WINAPI IsDBCSLeadByte(BYTE TestChar);
BOOL WINAPI IsDBCSLeadByteEx(UINT CodePage, BYTE TestChar);
int WINAPI LCMapStringW(LCID Locale, DWORD dwMapFlags, LPCWCH lpSrcStr, int cchSrc, LPWSTR lpDestStr, int cchDest);
int WINAPI LCMapStringA(LCID Locale, DWORD dwMapFlags, LPCCH lpSrcStr, int cchSrc, LPSTR lpDestStr, int cchDest);

} // namespace kernel32
