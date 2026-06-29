#include "user32.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "kernel32/internal.h"
#include "modules.h"
#include "resources.h"

#include <cstring>
#include <cwctype>

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

DWORD WINAPI CharUpperBuffW(LPWSTR lpsz, DWORD cchLength) {
	DEBUG_LOG("CharUpperBuffW(%p, %lu)\n", lpsz, static_cast<unsigned long>(cchLength));
	if (!lpsz) return 0;
	for (DWORD i = 0; i < cchLength; i++)
		lpsz[i] = static_cast<WCHAR>(std::towupper(lpsz[i]));
	return cchLength;
}

LPSTR WINAPI CharNextA(LPCSTR lpsz) {
	DEBUG_LOG("CharNextA(%p)\n", lpsz);
	if (!lpsz || !*lpsz) return const_cast<LPSTR>(lpsz);
	return const_cast<LPSTR>(lpsz + 1);
}

LONG WINAPI SendMessageA(HWND hWnd, UINT Msg, LONG wParam, LONG lParam) {
	// No-op stub. Real Windows returns 0 with ERROR_INVALID_WINDOW_HANDLE
	// when called with a NULL/invalid HWND. NT-era command-line tools (MC,
	// RC) link against user32 and keep a vestigial SendMessage call for
	// posting progress/errors to an IDE workbench HWND that's NULL in
	// standalone runs. We don't host any windows so every call here is
	// the NULL-HWND path.
	DEBUG_LOG("STUB: SendMessageA(hwnd=%p, msg=0x%x, w=0x%lx, l=0x%lx) -> 0\n", hWnd, Msg,
			  static_cast<unsigned long>(wParam), static_cast<unsigned long>(lParam));
	(void)hWnd; (void)Msg; (void)wParam; (void)lParam;
	kernel32::setLastError(ERROR_INVALID_WINDOW_HANDLE);
	return 0;
}

LONG WINAPI SendMessageW(HWND hWnd, UINT Msg, LONG wParam, LONG lParam) {
	DEBUG_LOG("STUB: SendMessageW(hwnd=%p, msg=0x%x, w=0x%lx, l=0x%lx) -> 0\n", hWnd, Msg,
			  static_cast<unsigned long>(wParam), static_cast<unsigned long>(lParam));
	(void)hWnd; (void)Msg; (void)wParam; (void)lParam;
	kernel32::setLastError(ERROR_INVALID_WINDOW_HANDLE);
	return 0;
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
