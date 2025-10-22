#include "common.h"
#include "context.h"
#include "modules.h"

namespace ole32 {
	int WIN_FUNC CoInitialize(void *pvReserved) {
		HOST_CONTEXT_GUARD();
		DEBUG_LOG("STUB: CoInitialize(%p)\n", pvReserved);
		(void) pvReserved;
		return 0; // S_OK
	}

	struct GUID {
		unsigned int Data1;
		unsigned short Data2;
		unsigned short Data3;
		unsigned char Data4[8];
	};

	int WIN_FUNC CoCreateInstance(
		const GUID *rclsid,
		void *pUnkOuter,
		unsigned int dwClsContext,
		const GUID *riid,
		void **ppv
	) {
		HOST_CONTEXT_GUARD();
		DEBUG_LOG("STUB: CoCreateInstance(0x%x, %p, %d, 0x%x, %p)\n", rclsid->Data1, pUnkOuter, dwClsContext, riid->Data1, *ppv);
		*ppv = 0;
		// E_POINTER is returned when ppv is NULL, which isn't true here, but returning 1 results
		// in a segfault with mwcceppc.exe when it's told to include directories that don't exist
		return 0x80004003; // E_POINTER
	}

	int WIN_FUNC CLSIDFromString(const wchar_t *lpsz, ole32::GUID *pclsid) {
		if (!pclsid)
			return (int)0x80070057; // E_INVALIDARG

		memset(pclsid, 0, sizeof(*pclsid));
		return 0; // S_OK
	}
}

static void *resolveByName(const char *name) {
	if (strcmp(name, "CoInitialize") == 0) return (void *) ole32::CoInitialize;
	if (strcmp(name, "CoCreateInstance") == 0) return (void *) ole32::CoCreateInstance;
	if (strcmp(name, "CLSIDFromString") == 0) return (void *) ole32::CLSIDFromString;
	return nullptr;
}

extern const wibo::ModuleStub lib_ole32 = {
	(const char *[]){
		"ole32",
		nullptr,
	},
	resolveByName,
	nullptr,
};
