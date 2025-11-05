#include "user32.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "kernel32/internal.h"
#include "modules.h"
#include "resources.h"

#include <cstring>

namespace user32 {

constexpr uint32_t RT_STRING_ID = 6;
constexpr HKL kDefaultKeyboardLayout = 0x04090409;
constexpr int UOI_FLAGS = 1;
constexpr DWORD WSF_VISIBLE = 0x0001;

struct USEROBJECTFLAGS {
	BOOL fInherit;
	BOOL fReserved;
	DWORD dwFlags;
};

int WINAPI LoadStringA(HMODULE hInstance, UINT uID, LPSTR lpBuffer, int cchBufferMax) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("LoadStringA(%p, %u, %p, %d)\n", hInstance, uID, lpBuffer, cchBufferMax);
	if (!lpBuffer || cchBufferMax <= 0) {
		return 0;
	}
	wibo::Executable *mod = wibo::executableFromModule((HMODULE)hInstance);
	if (!mod) {
		return 0;
	}
	wibo::ResourceIdentifier type = wibo::ResourceIdentifier::fromID(RT_STRING_ID);
	wibo::ResourceIdentifier table = wibo::ResourceIdentifier::fromID((uID >> 4) + 1);
	wibo::ResourceLocation loc;
	if (!mod->findResource(type, table, std::nullopt, loc)) {
		return 0;
	}
	const uint16_t *cursor = reinterpret_cast<const uint16_t *>(loc.data);
	const uint16_t *end = cursor + (loc.size / sizeof(uint16_t));
	unsigned int entryIndex = uID & 0x0Fu;
	for (unsigned int i = 0; i < entryIndex; ++i) {
		if (cursor >= end) {
			return 0;
		}
		uint16_t length = *cursor++;
		if (cursor + length > end) {
			return 0;
		}
		cursor += length;
	}
	if (cursor >= end) {
		return 0;
	}
	uint16_t length = *cursor++;
	if (cursor + length > end) {
		return 0;
	}
	int copyLength = length;
	if (copyLength > cchBufferMax - 1) {
		copyLength = cchBufferMax - 1;
	}
	for (int i = 0; i < copyLength; ++i) {
		lpBuffer[i] = static_cast<char>(cursor[i] & 0xFF);
	}
	lpBuffer[copyLength] = 0;
	DEBUG_LOG("LoadStringA -> %.*s\n", copyLength, lpBuffer);
	return copyLength;
}

int WINAPI LoadStringW(HMODULE hInstance, UINT uID, LPWSTR lpBuffer, int cchBufferMax) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("LoadStringW(%p, %u, %p, %d)\n", hInstance, uID, lpBuffer, cchBufferMax);
	wibo::Executable *mod = wibo::executableFromModule((HMODULE)hInstance);
	if (!mod) {
		return 0;
	}
	wibo::ResourceIdentifier type = wibo::ResourceIdentifier::fromID(RT_STRING_ID);
	wibo::ResourceIdentifier table = wibo::ResourceIdentifier::fromID((uID >> 4) + 1);
	wibo::ResourceLocation loc;
	if (!mod->findResource(type, table, std::nullopt, loc)) {
		return 0;
	}
	const uint16_t *cursor = reinterpret_cast<const uint16_t *>(loc.data);
	const uint16_t *end = cursor + (loc.size / sizeof(uint16_t));
	unsigned int entryIndex = uID & 0x0Fu;
	for (unsigned int i = 0; i < entryIndex; ++i) {
		if (cursor >= end) {
			return 0;
		}
		uint16_t length = *cursor++;
		if (cursor + length > end) {
			return 0;
		}
		cursor += length;
	}
	if (cursor >= end) {
		return 0;
	}
	uint16_t length = *cursor++;
	if (cursor + length > end) {
		return 0;
	}
	if (cchBufferMax == 0) {
		if (lpBuffer) {
			*reinterpret_cast<uint16_t **>(lpBuffer) = const_cast<uint16_t *>(cursor);
		}
		return length;
	}
	if (!lpBuffer || cchBufferMax <= 0) {
		return 0;
	}
	int copyLength = length;
	if (copyLength > cchBufferMax - 1) {
		copyLength = cchBufferMax - 1;
	}
	for (int i = 0; i < copyLength; ++i) {
		lpBuffer[i] = cursor[i];
	}
	lpBuffer[copyLength] = 0;
	DEBUG_LOG("LoadStringW -> length %d\n", copyLength);
	return copyLength;
}

int WINAPI MessageBoxA(HWND hwnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	HOST_CONTEXT_GUARD();
	(void)hwnd;
	(void)uType;
	printf("MESSAGE BOX: [%s] %s\n", lpCaption, lpText);
	fflush(stdout);
	return 1;
}

HKL WINAPI GetKeyboardLayout(DWORD idThread) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: GetKeyboardLayout(%u)\n", idThread);
	(void)idThread;
	return kDefaultKeyboardLayout;
}

HWINSTA WINAPI GetProcessWindowStation() {
	DEBUG_LOG("STUB: GetProcessWindowStation()\n");
	return NO_HANDLE;
}

BOOL WINAPI GetUserObjectInformationA(HANDLE hObj, int nIndex, PVOID pvInfo, DWORD nLength, LPDWORD lpnLengthNeeded) {
	DEBUG_LOG("GetUserObjectInformationA(%p, %d, %p, %u, %p)\n", hObj, nIndex, pvInfo, nLength, lpnLengthNeeded);
	(void)hObj;

	if (lpnLengthNeeded) {
		*lpnLengthNeeded = sizeof(USEROBJECTFLAGS);
	}

	if (nIndex != UOI_FLAGS) {
		kernel32::setLastError(ERROR_CALL_NOT_IMPLEMENTED);
		return FALSE;
	}

	if (!pvInfo || nLength < sizeof(USEROBJECTFLAGS)) {
		kernel32::setLastError(ERROR_INSUFFICIENT_BUFFER);
		return FALSE;
	}

	auto *flags = reinterpret_cast<USEROBJECTFLAGS *>(pvInfo);
	flags->fInherit = FALSE;
	flags->fReserved = FALSE;
	flags->dwFlags = WSF_VISIBLE;
	return TRUE;
}

HWND WINAPI GetActiveWindow() {
	DEBUG_LOG("GetActiveWindow()\n");
	return NO_HANDLE;
}

} // namespace user32

#include "user32_trampolines.h"

extern const wibo::ModuleStub lib_user32 = {
	(const char *[]){
		"user32",
		nullptr,
	},
	user32ThunkByName,
	nullptr,
};
