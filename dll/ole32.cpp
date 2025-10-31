#include "ole32.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "modules.h"

#include <cstring>

namespace {
constexpr HRESULT E_INVALIDARG = static_cast<HRESULT>(0x80070057);
constexpr HRESULT CO_E_CLASSSTRING = static_cast<HRESULT>(0x800401F3);
constexpr GUID kGuidNull = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0}};

bool hexDigitValue(uint16_t codeUnit, uint8_t &value) {
	if (codeUnit >= '0' && codeUnit <= '9') {
		value = static_cast<uint8_t>(codeUnit - '0');
		return true;
	}
	if (codeUnit >= 'a' && codeUnit <= 'f') {
		value = static_cast<uint8_t>(10 + codeUnit - 'a');
		return true;
	}
	if (codeUnit >= 'A' && codeUnit <= 'F') {
		value = static_cast<uint8_t>(10 + codeUnit - 'A');
		return true;
	}
	return false;
}

bool parseFixedHex(const uint16_t *&cursor, size_t digits, uint64_t &valueOut) {
	valueOut = 0;
	for (size_t i = 0; i < digits; ++i) {
		uint16_t codeUnit = cursor[i];
		uint8_t digitValue = 0;
		if (!hexDigitValue(codeUnit, digitValue)) {
			return false;
		}
		valueOut = (valueOut << 4) | digitValue;
	}
	cursor += digits;
	return true;
}

bool expectChar(const uint16_t *&cursor, uint16_t expected) {
	if (*cursor != expected) {
		return false;
	}
	++cursor;
	return true;
}

HRESULT parseGuidString(const uint16_t *first, const uint16_t *last, GUID &out) {
	const uint16_t *cursor = first;

	if (cursor >= last) {
		return CO_E_CLASSSTRING;
	}

	if (*cursor != '{') {
		return CO_E_CLASSSTRING;
	}

	++cursor;
	if (cursor >= last || *(last - 1) != '}') {
		return CO_E_CLASSSTRING;
	}
	--last;

	if (static_cast<size_t>(last - cursor) != 36) {
		return CO_E_CLASSSTRING;
	}

	uint64_t data1 = 0;
	if (!parseFixedHex(cursor, 8, data1) || !expectChar(cursor, '-'))
		return CO_E_CLASSSTRING;

	uint64_t data2 = 0;
	if (!parseFixedHex(cursor, 4, data2) || !expectChar(cursor, '-'))
		return CO_E_CLASSSTRING;

	uint64_t data3 = 0;
	if (!parseFixedHex(cursor, 4, data3) || !expectChar(cursor, '-'))
		return CO_E_CLASSSTRING;

	uint64_t data4Prefix = 0;
	if (!parseFixedHex(cursor, 4, data4Prefix) || !expectChar(cursor, '-'))
		return CO_E_CLASSSTRING;

	uint64_t data4Suffix = 0;
	if (!parseFixedHex(cursor, 12, data4Suffix))
		return CO_E_CLASSSTRING;

	if (cursor != last) {
		return CO_E_CLASSSTRING;
	}

	out.Data1 = static_cast<unsigned int>(data1);
	out.Data2 = static_cast<unsigned short>(data2);
	out.Data3 = static_cast<unsigned short>(data3);
	out.Data4[0] = static_cast<unsigned char>((data4Prefix >> 8) & 0xFF);
	out.Data4[1] = static_cast<unsigned char>(data4Prefix & 0xFF);
	for (int i = 0; i < 6; ++i) {
		int shift = (5 - i) * 8;
		out.Data4[2 + i] = static_cast<unsigned char>((data4Suffix >> shift) & 0xFF);
	}

	return S_OK;
}
} // namespace

namespace ole32 {

HRESULT WINAPI CoInitialize(LPVOID pvReserved) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: CoInitialize(%p)\n", pvReserved);
	(void)pvReserved;
	return 0; // S_OK
}

HRESULT WINAPI CoCreateInstance(const GUID *rclsid, LPVOID pUnkOuter, DWORD dwClsContext, const GUID *riid,
								LPVOID *ppv) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: CoCreateInstance(0x%x, %p, %d, 0x%x, %p)\n", rclsid->Data1, pUnkOuter, dwClsContext, riid->Data1,
			  *ppv);
	*ppv = 0;
	// E_POINTER is returned when ppv is NULL, which isn't true here, but returning 1 results
	// in a segfault with mwcceppc.exe when it's told to include directories that don't exist
	return 0x80004003; // E_POINTER
}

HRESULT WINAPI CLSIDFromString(LPCWSTR lpsz, GUID *pclsid) {
	HOST_CONTEXT_GUARD();

	if (pclsid == nullptr) {
		return E_INVALIDARG;
	}

	if (lpsz == nullptr) {
		*pclsid = kGuidNull;
		return S_OK;
	}

	const uint16_t *begin = lpsz;
	const uint16_t *end = begin;
	while (*end) {
		++end;
	}

	if (begin == end) {
		return CO_E_CLASSSTRING;
	}

	return parseGuidString(begin, end, *pclsid);
}

} // namespace ole32

#include "ole32_trampolines.h"

extern const wibo::ModuleStub lib_ole32 = {
	(const char *[]){
		"ole32",
		nullptr,
	},
	ole32ThunkByName,
	nullptr,
};
