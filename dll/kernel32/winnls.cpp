#include "winnls.h"

#include "context.h"
#include "errors.h"
#include "heap.h"
#include "internal.h"
#include "kernel32.h"
#include "kernel32_trampolines.h"
#include "strutil.h"

#include <algorithm>
#include <cstring>
#include <initializer_list>
#include <string>
#include <vector>

namespace {

constexpr DWORD kNormIgnoreCase = 0x00000001;
constexpr DWORD LCID_INSTALLED = 0x00000001;
constexpr DWORD LCID_SUPPORTED = 0x00000002;
constexpr DWORD LCID_ALTERNATE_SORTS = 0x00000004;
constexpr LCID kEnUsLcid = 0x0409;
constexpr LCID kInvariantLcid = 0x007f;
constexpr DWORD LOCALE_ALLOW_NEUTRAL_NAMES = 0x08000000;
constexpr DWORD kLocaleNoUserOverride = 0x80000000u;
constexpr DWORD kLocaleReturnNumber = 0x20000000u;
constexpr DWORD kLocaleFlagMask = 0xF0000000u;

int compareStrings(const std::string &a, const std::string &b, DWORD dwCmpFlags) {
	for (size_t i = 0;; ++i) {
		if (i == a.size()) {
			if (i == b.size()) {
				return 2; // CSTR_EQUAL
			}
			return 1; // CSTR_LESS_THAN
		}
		if (i == b.size()) {
			return 3; // CSTR_GREATER_THAN
		}
		unsigned char c = static_cast<unsigned char>(a[i]);
		unsigned char d = static_cast<unsigned char>(b[i]);
		if (dwCmpFlags & kNormIgnoreCase) {
			if (c >= 'a' && c <= 'z') {
				c = static_cast<unsigned char>(c - ('a' - 'A'));
			}
			if (d >= 'a' && d <= 'z') {
				d = static_cast<unsigned char>(d - ('a' - 'A'));
			}
		}
		if (c != d) {
			return (c < d) ? 1 : 3;
		}
	}
}

std::string localeInfoString(int LCType) {
	switch (LCType) {
	case 4100: // LOCALE_IDEFAULTANSICODEPAGE
		return "28591";
	case 4097: // LOCALE_SENGLANGUAGE
		return "Lang";
	case 4098: // LOCALE_SENGCOUNTRY
		return "Country";
	case 0x1: // LOCALE_ILANGUAGE
		return "0001";
	case 0x15: // LOCALE_SINTLSYMBOL
		return "Currency";
	case 0x14: // LOCALE_SCURRENCY
		return "sCurrency";
	case 0x16: // LOCALE_SMONDECIMALSEP
		return ".";
	case 0x17: // LOCALE_SMONTHOUSANDSEP
		return ",";
	case 0x18: // LOCALE_SMONGROUPING
		return ";";
	case 0x50: // LOCALE_SPOSITIVESIGN
		return "";
	case 0x51: // LOCALE_SNEGATIVESIGN
		return "-";
	case 0x1A: // LOCALE_IINTLCURRDIGITS
	case 0x19: // LOCALE_ICURRDIGITS
		return "2";
	default:
		DEBUG_LOG("STUB: GetLocaleInfo LCType 0x%x not implemented\n", LCType);
		return "";
	}
}

} // namespace

namespace kernel32 {

UINT WINAPI GetACP() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetACP() -> %u\n", 28591);
	return 28591; // Latin1 (ISO/IEC 8859-1)
}

LANGID WINAPI GetSystemDefaultLangID() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: GetSystemDefaultLangID()\n");
	return 0;
}

LANGID WINAPI GetUserDefaultUILanguage() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: GetUserDefaultUILanguage()\n");
	return 0;
}

int WINAPI GetUserDefaultLocaleName(LPWSTR lpLocaleName, int cchLocaleName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetUserDefaultLocaleName(%p, %d)\n", lpLocaleName, cchLocaleName);
	if (!lpLocaleName || cchLocaleName < 0) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	constexpr char16_t localeName[] = u"en-US";
	constexpr int requiredChars = static_cast<int>(sizeof(localeName) / sizeof(char16_t));
	if (cchLocaleName < requiredChars) {
		setLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}

	std::memcpy(lpLocaleName, localeName, sizeof(localeName));
	return requiredChars;
}

LCID WINAPI LocaleNameToLCID(LPCWSTR lpName, DWORD dwFlags) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("LocaleNameToLCID(%p, 0x%x)\n", lpName, dwFlags);
	if (dwFlags & ~LOCALE_ALLOW_NEUTRAL_NAMES) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	if (!lpName) {
		return kEnUsLcid;
	}

	std::string localeName = wideStringToString(lpName);
	if (localeName.empty()) {
		return kInvariantLcid;
	}

	std::string normalized = stringToLower(localeName);
	if (normalized == "en-us" || normalized == "en_us" || normalized == "!x-sys-default-locale") {
		return kEnUsLcid;
	}

	setLastError(ERROR_INVALID_PARAMETER);
	return 0;
}

BOOL WINAPI GetCPInfo(UINT CodePage, LPCPINFO lpCPInfo) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetCPInfo(%u, %p)\n", CodePage, lpCPInfo);
	(void)CodePage;

	if (!lpCPInfo) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	lpCPInfo->MaxCharSize = 1;
	std::fill(lpCPInfo->DefaultChar, lpCPInfo->DefaultChar + MAX_DEFAULTCHAR, 0);
	lpCPInfo->DefaultChar[0] = '?';
	std::fill(lpCPInfo->LeadByte, lpCPInfo->LeadByte + MAX_LEADBYTES, 0);
	return TRUE;
}

int WINAPI CompareStringA(LCID Locale, DWORD dwCmpFlags, LPCSTR lpString1, int cchCount1, LPCSTR lpString2,
						  int cchCount2) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CompareStringA(%u, %u, %s, %d, %s, %d)\n", Locale, dwCmpFlags, lpString1 ? lpString1 : "(null)",
			  cchCount1, lpString2 ? lpString2 : "(null)", cchCount2);
	(void)Locale;
	if (!lpString1 || !lpString2) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	if (cchCount1 < 0) {
		cchCount1 = static_cast<int>(strlen(lpString1));
	}
	if (cchCount2 < 0) {
		cchCount2 = static_cast<int>(strlen(lpString2));
	}

	std::string str1(lpString1, lpString1 + cchCount1);
	std::string str2(lpString2, lpString2 + cchCount2);
	return compareStrings(str1, str2, dwCmpFlags);
}

int WINAPI CompareStringW(LCID Locale, DWORD dwCmpFlags, LPCWCH lpString1, int cchCount1, LPCWCH lpString2,
						  int cchCount2) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CompareStringW(%u, %u, %p, %d, %p, %d)\n", Locale, dwCmpFlags, lpString1, cchCount1, lpString2,
			  cchCount2);
	(void)Locale;
	if (!lpString1 || !lpString2) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	std::string str1 = wideStringToString(lpString1, cchCount1);
	std::string str2 = wideStringToString(lpString2, cchCount2);
	return compareStrings(str1, str2, dwCmpFlags);
}

BOOL WINAPI IsValidCodePage(UINT CodePage) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("IsValidCodePage(%u)\n", CodePage);
	(void)CodePage;
	return TRUE;
}

BOOL WINAPI IsValidLocale(LCID Locale, DWORD dwFlags) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("IsValidLocale(%u, 0x%x)\n", Locale, dwFlags);
	(void)Locale;
	if (dwFlags != 0 && (dwFlags & ~(LCID_INSTALLED | LCID_SUPPORTED | LCID_ALTERNATE_SORTS)) != 0) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	return TRUE;
}

int WINAPI GetLocaleInfoA(LCID Locale, LCTYPE LCType, LPSTR lpLCData, int cchData) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetLocaleInfoA(%u, %u, %p, %d)\n", Locale, LCType, lpLCData, cchData);
	(void)Locale;

	std::string value = localeInfoString(static_cast<int>(LCType));
	size_t required = value.size() + 1;

	if (cchData == 0) {
		return static_cast<int>(required);
	}
	if (!lpLCData || cchData < 0) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	if (static_cast<size_t>(cchData) < required) {
		setLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}

	std::memcpy(lpLCData, value.c_str(), required);
	return static_cast<int>(required);
}

int WINAPI GetLocaleInfoW(LCID Locale, LCTYPE LCType, LPWSTR lpLCData, int cchData) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetLocaleInfoW(%u, %u, %p, %d)\n", Locale, LCType, lpLCData, cchData);
	(void)Locale;

	std::string info = localeInfoString(static_cast<int>(LCType));
	auto wide = stringToWideString(info.c_str());
	size_t required = wide.size();

	if (cchData == 0) {
		return static_cast<int>(required);
	}
	if (!lpLCData || cchData < 0) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	if (static_cast<size_t>(cchData) < required) {
		setLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}

	std::memcpy(lpLCData, wide.data(), required * sizeof(uint16_t));
	return static_cast<int>(required);
}

int WINAPI GetLocaleInfoEx(LPCWSTR lpLocaleName, LCTYPE LCType, LPWSTR lpLCData, int cchData) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetLocaleInfoEx(%p, %u, %p, %d)\n", lpLocaleName, LCType, lpLCData, cchData);

	if (cchData < 0) {
		setLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}

	DWORD lctypeFlags = static_cast<DWORD>(LCType) & kLocaleFlagMask;
	constexpr DWORD kSupportedFlags = kLocaleNoUserOverride;
	if ((lctypeFlags & kLocaleReturnNumber) != 0 || (lctypeFlags & ~kSupportedFlags) != 0) {
		setLastError(ERROR_INVALID_FLAGS);
		return 0;
	}

	if (lpLocaleName) {
		std::string localeName = wideStringToString(reinterpret_cast<const uint16_t *>(lpLocaleName));
		std::string normalized = stringToLower(localeName);
		if (!normalized.empty() && normalized != "en-us" && normalized != "en_us" &&
			normalized != "!x-sys-default-locale") {
			DEBUG_LOG("GetLocaleInfoEx: unsupported locale name '%s'\n", localeName.c_str());
			setLastError(ERROR_INVALID_PARAMETER);
			return 0;
		}
	}

	DWORD baseType = static_cast<DWORD>(LCType) & ~kLocaleFlagMask;
	std::string info = localeInfoString(static_cast<int>(baseType));
	auto wide = stringToWideString(info.c_str());
	size_t required = wide.size();

	if (cchData == 0) {
		return static_cast<int>(required);
	}
	if (!lpLCData) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	if (static_cast<size_t>(cchData) < required) {
		setLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}

	std::memcpy(lpLCData, wide.data(), required * sizeof(uint16_t));
	return static_cast<int>(required);
}

BOOL WINAPI EnumSystemLocalesA(LOCALE_ENUMPROCA lpLocaleEnumProc, DWORD dwFlags) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("EnumSystemLocalesA(%p, 0x%x)\n", lpLocaleEnumProc, dwFlags);
	(void)dwFlags;
	if (!lpLocaleEnumProc) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	constexpr char defaultLocaleId[] = "00000409"; // en-US
	char *localeId = reinterpret_cast<char *>(wibo::heap::guestMalloc(sizeof(defaultLocaleId)));
	if (!localeId) {
		setLastError(ERROR_NOT_ENOUGH_MEMORY);
		return FALSE;
	}
	std::memcpy(localeId, defaultLocaleId, sizeof(defaultLocaleId));
	BOOL ret = call_LOCALE_ENUMPROCA(lpLocaleEnumProc, localeId);
	wibo::heap::guestFree(localeId);
	return ret;
}

LCID WINAPI GetUserDefaultLCID() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: GetUserDefaultLCID()\n");
	return 0x0409; // en-US
}

BOOL WINAPI IsDBCSLeadByte(BYTE TestChar) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: IsDBCSLeadByte(%u)\n", TestChar);
	(void)TestChar;
	return FALSE;
}

BOOL WINAPI IsDBCSLeadByteEx(UINT CodePage, BYTE TestChar) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("IsDBCSLeadByteEx(%u, %u)\n", CodePage, TestChar);

	auto inRanges = [TestChar](std::initializer_list<std::pair<uint8_t, uint8_t>> ranges) -> BOOL {
		for (const auto &range : ranges) {
			if (TestChar >= range.first && TestChar <= range.second) {
				return TRUE;
			}
		}
		return FALSE;
	};

	setLastError(ERROR_SUCCESS);
	switch (CodePage) {
	case 932: // Shift-JIS
		return inRanges({{0x81, 0x9F}, {0xE0, 0xFC}});
	case 936:  // GBK
	case 949:  // Korean
	case 950:  // Big5
	case 1361: // Johab
		return inRanges({{0x81, 0xFE}});
	case 0: // CP_ACP
	case 1: // CP_OEMCP
	case 2: // CP_MACCP
	case 3: // CP_THREAD_ACP
	default:
		return FALSE;
	}
}

int WINAPI LCMapStringW(LCID Locale, DWORD dwMapFlags, LPCWCH lpSrcStr, int cchSrc, LPWSTR lpDestStr, int cchDest) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("LCMapStringW(%u, 0x%x, %p, %d, %p, %d)\n", Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest);
	(void)Locale;
	if (!lpSrcStr || cchSrc == 0) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	bool nullTerminated = cchSrc < 0;
	size_t srcLen = nullTerminated ? (wstrlen(lpSrcStr) + 1) : static_cast<size_t>(cchSrc);
	if (srcLen == 0) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	if (!lpDestStr || cchDest == 0) {
		return static_cast<int>(srcLen);
	}
	if (cchDest < static_cast<int>(srcLen)) {
		setLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}

	if (dwMapFlags & (0x00000400u | 0x00000800u)) { // LCMAP_SORTKEY | LCMAP_BYTEREV
		DEBUG_LOG("LCMapStringW: unsupported mapping flags 0x%x\n", dwMapFlags);
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	unsigned int casingFlags = dwMapFlags & (0x00000200u | 0x00000100u); // UPPERCASE | LOWERCASE
	std::vector<uint16_t> buffer(srcLen, 0);
	for (size_t i = 0; i < srcLen; ++i) {
		uint16_t ch = lpSrcStr[i];
		if (casingFlags == 0x00000200u) {
			buffer[i] = wcharToUpper(ch);
		} else if (casingFlags == 0x00000100u) {
			buffer[i] = wcharToLower(ch);
		} else {
			buffer[i] = ch;
		}
	}

	std::memcpy(lpDestStr, buffer.data(), srcLen * sizeof(uint16_t));
	return static_cast<int>(srcLen);
}

int WINAPI LCMapStringA(LCID Locale, DWORD dwMapFlags, LPCCH lpSrcStr, int cchSrc, LPSTR lpDestStr, int cchDest) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("LCMapStringA(%u, 0x%x, %p, %d, %p, %d)\n", Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest);
	if (!lpSrcStr) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	int length = cchSrc;
	if (length < 0) {
		length = static_cast<int>(strlen(lpSrcStr)) + 1;
	}

	auto wideSrc = stringToWideString(lpSrcStr, static_cast<size_t>(length));
	std::vector<uint16_t> wideDest(std::max(cchDest, 0));
	int wideResult =
		LCMapStringW(Locale, dwMapFlags, wideSrc.data(), length, wideDest.empty() ? nullptr : wideDest.data(), cchDest);
	if (wideResult == 0) {
		setLastError(ERROR_SUCCESS);
		return 0;
	}

	if (!lpDestStr || cchDest == 0) {
		return wideResult;
	}

	auto mapped = wideStringToString(wideDest.data(), wideResult);
	size_t bytesToCopy = mapped.size() + 1;
	if (static_cast<size_t>(cchDest) < bytesToCopy) {
		setLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}
	std::memcpy(lpDestStr, mapped.c_str(), bytesToCopy);
	return wideResult;
}

} // namespace kernel32
