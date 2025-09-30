#include "common.h"
#include "errors.h"
#include "handles.h"

namespace psapi {
BOOL WIN_FUNC EnumProcessModules(HANDLE hProcess, HMODULE *lphModule, DWORD cb, DWORD *lpcbNeeded) {
	DEBUG_LOG("EnumProcessModules(hProcess=%p, cb=%u)\n", hProcess, cb);

	bool recognizedHandle = false;
	if (hProcess == (HANDLE)0xFFFFFFFF) {
		recognizedHandle = true;
	} else {
		auto data = handles::dataFromHandle(hProcess, false);
		recognizedHandle = (data.type == handles::TYPE_PROCESS);
	}
	if (!recognizedHandle) {
		wibo::lastError = ERROR_ACCESS_DENIED;
		return FALSE;
	}

	HMODULE currentModule = wibo::mainModule ? wibo::mainModule->handle : nullptr;
	DWORD required = currentModule ? sizeof(HMODULE) : 0;
	if (lpcbNeeded) {
		*lpcbNeeded = required;
	}

	if (required == 0) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}

	if (!lphModule || cb < required) {
		wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
		return FALSE;
	}

	lphModule[0] = currentModule;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}
} // namespace psapi

static void *resolveByName(const char *name) {
	if (strcmp(name, "EnumProcessModules") == 0)
		return (void *)psapi::EnumProcessModules;
	if (strcmp(name, "K32EnumProcessModules") == 0)
		return (void *)psapi::EnumProcessModules;
	return nullptr;
}

static void *resolveByOrdinal(uint16_t ordinal) {
	switch (ordinal) {
	case 4: // EnumProcessModules
		return (void *)psapi::EnumProcessModules;
	default:
		return nullptr;
	}
}

wibo::Module lib_psapi = {
	(const char *[]){
		"psapi",
		"psapi.dll",
		nullptr,
	},
	resolveByName,
	resolveByOrdinal,
};
