#include "common.h"

namespace ole32 {
	int WIN_FUNC CoInitialize(void *pvReserved) {
		DEBUG_LOG("CoInitialize(...)\n");
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
		// when license.dat is missing:
		// rclsid = CLSID_ShellLink (0x21401), riid = IID_IShellLinkA (0x214ee)
		// and then it crashes with a null pointer deref
		DEBUG_LOG("CoCreateInstance 0x%x %p %d 0x%x %p\n", rclsid->Data1, pUnkOuter, dwClsContext, riid->Data1, *ppv);
		*ppv = 0;
		return 1;
	}
}

static void *resolveByName(const char *name) {
	if (strcmp(name, "CoInitialize") == 0) return (void *) ole32::CoInitialize;
	if (strcmp(name, "CoCreateInstance") == 0) return (void *) ole32::CoCreateInstance;
	return nullptr;
}

wibo::Module lib_ole32 = {
	(const char *[]){
		"ole32",
		"ole32.dll",
		nullptr,
	},
	resolveByName,
	nullptr,
};
