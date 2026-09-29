#include "macros.h"
#include "modules.h"

INCLUDE_BIN(_crtdllDllData, EMBED_PATH)

extern const wibo::ModuleStub lib_crtdll = {
	.names =
		(const char *[]){
			"crtdll",
			nullptr,
		},
	.dllData = INCLUDE_BIN_SPAN(_crtdllDllData),
};
