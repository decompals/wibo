#include "stringapiset.h"

#include "context.h"
#include "errors.h"
#include "strutil.h"

#include <cstring>
#include <cwctype>
#include <string>
#include <vector>

namespace kernel32 {

int WIN_FUNC WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar,
								 LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("WideCharToMultiByte(%u, %u, %p, %d, %p, %d, %p, %p)\n", CodePage, dwFlags, lpWideCharStr, cchWideChar,
			  lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);

	(void)CodePage;
	(void)dwFlags;
	(void)lpDefaultChar;
	if (lpUsedDefaultChar) {
		*lpUsedDefaultChar = FALSE;
	}

	if (cchWideChar == -1) {
		cchWideChar = static_cast<int>(wstrlen(lpWideCharStr)) + 1;
	}

	if (cbMultiByte == 0) {
		return cchWideChar;
	}
	for (int i = 0; i < cchWideChar; i++) {
		lpMultiByteStr[i] = static_cast<char>(lpWideCharStr[i] & 0xFF);
	}

	if (wibo::debugEnabled) {
		std::string s(lpMultiByteStr, lpMultiByteStr + cchWideChar);
		DEBUG_LOG("Converted string: [%s] (len %d)\n", s.c_str(), cchWideChar);
	}

	return cchWideChar;
}

int WIN_FUNC MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte,
								 LPWSTR lpWideCharStr, int cchWideChar) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("MultiByteToWideChar(%u, %u, %d, %d)\n", CodePage, dwFlags, cbMultiByte, cchWideChar);

	(void)CodePage;
	(void)dwFlags;

	if (cbMultiByte == -1) {
		cbMultiByte = static_cast<int>(strlen(lpMultiByteStr)) + 1;
	}

	if (cchWideChar == 0) {
		return cbMultiByte;
	}
	if (wibo::debugEnabled) {
		std::string s(lpMultiByteStr, lpMultiByteStr + cbMultiByte);
		DEBUG_LOG("Converting string: [%s] (len %d)\n", s.c_str(), cbMultiByte);
	}

	assert(cbMultiByte <= cchWideChar);
	for (int i = 0; i < cbMultiByte; i++) {
		lpWideCharStr[i] = static_cast<uint16_t>(lpMultiByteStr[i] & 0xFF);
	}
	return cbMultiByte;
}

BOOL WIN_FUNC GetStringTypeW(DWORD dwInfoType, LPCWCH lpSrcStr, int cchSrc, LPWORD lpCharType) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetStringTypeW(%u, %p, %i, %p)\n", dwInfoType, lpSrcStr, cchSrc, lpCharType);

	assert(dwInfoType == 1); // CT_CTYPE1

	if (!lpSrcStr || !lpCharType) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	if (cchSrc < 0) {
		cchSrc = static_cast<int>(wstrlen(lpSrcStr));
	}

	for (int i = 0; i < cchSrc; i++) {
		wint_t c = lpSrcStr[i];
		bool upper = std::iswupper(c);
		bool lower = std::iswlower(c);
		bool alpha = std::iswalpha(c);
		bool digit = std::iswdigit(c);
		bool space = std::iswspace(c);
		bool blank = (c == L' ' || c == L'\t');
		bool hex = std::iswxdigit(c);
		bool cntrl = std::iswcntrl(c);
		bool punct = std::iswpunct(c);
		lpCharType[i] = (upper ? 1 : 0) | (lower ? 2 : 0) | (digit ? 4 : 0) | (space ? 8 : 0) | (punct ? 0x10 : 0) |
						(cntrl ? 0x20 : 0) | (blank ? 0x40 : 0) | (hex ? 0x80 : 0) | (alpha ? 0x100 : 0);
	}

	return TRUE;
}

BOOL WIN_FUNC GetStringTypeA(LCID Locale, DWORD dwInfoType, LPCSTR lpSrcStr, int cchSrc, LPWORD lpCharType) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetStringTypeA(%u, %u, %p, %d, %p)\n", Locale, dwInfoType, lpSrcStr, cchSrc, lpCharType);
	(void)Locale;

	if (!lpSrcStr || !lpCharType) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	if (dwInfoType != 1) {
		wibo::lastError = ERROR_NOT_SUPPORTED;
		return FALSE;
	}

	int length = cchSrc;
	if (length < 0) {
		length = static_cast<int>(strlen(lpSrcStr));
	}
	if (length < 0) {
		length = 0;
	}

	std::vector<uint16_t> wide;
	wide.reserve(static_cast<size_t>(length));
	for (int i = 0; i < length; ++i) {
		wide.push_back(static_cast<unsigned char>(lpSrcStr[i]));
	}

	if (length > 0) {
		return GetStringTypeW(dwInfoType, wide.data(), length, lpCharType);
	} 
	return TRUE;
}

} // namespace kernel32
