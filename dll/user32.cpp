#include "common.h"
#include "errors.h"
#include "strutil.h"

namespace user32 {
	constexpr uint32_t RT_STRING_ID = 6;
	constexpr uintptr_t kDefaultKeyboardLayout = 0x04090409;

	int WIN_FUNC LoadStringA(void* hInstance, unsigned int uID, char* lpBuffer, int cchBufferMax) {
		DEBUG_LOG("LoadStringA(%p, %u, %p, %d)\n", hInstance, uID, lpBuffer, cchBufferMax);
		if (!lpBuffer || cchBufferMax <= 0) {
			return 0;
		}
		wibo::Executable *mod = wibo::executableFromModule((HMODULE) hInstance);
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

	int WIN_FUNC LoadStringW(void* hInstance, unsigned int uID, uint16_t* lpBuffer, int cchBufferMax) {
		DEBUG_LOG("LoadStringW(%p, %u, %p, %d)\n", hInstance, uID, lpBuffer, cchBufferMax);
		wibo::Executable *mod = wibo::executableFromModule((HMODULE) hInstance);
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

	int WIN_FUNC MessageBoxA(void *hwnd, const char *lpText, const char *lpCaption, unsigned int uType) {
		printf("MESSAGE BOX: [%s] %s\n", lpCaption, lpText);
		fflush(stdout);
		return 1;
	}

	HKL WIN_FUNC GetKeyboardLayout(DWORD idThread) {
		DEBUG_LOG("GetKeyboardLayout(%u)\n", idThread);
		(void)idThread;
		wibo::lastError = ERROR_SUCCESS;
		return reinterpret_cast<HKL>(kDefaultKeyboardLayout);
	}
}


static void *resolveByName(const char *name) {
	if (strcmp(name, "LoadStringA") == 0) return (void *) user32::LoadStringA;
	if (strcmp(name, "LoadStringW") == 0) return (void *) user32::LoadStringW;
	if (strcmp(name, "MessageBoxA") == 0) return (void *) user32::MessageBoxA;
	if (strcmp(name, "GetKeyboardLayout") == 0) return (void *) user32::GetKeyboardLayout;
	return nullptr;
}

wibo::Module lib_user32 = {
	(const char *[]){
		"user32",
		nullptr,
	},
	resolveByName,
	nullptr,
};
