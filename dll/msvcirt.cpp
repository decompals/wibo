#include "macros.h"
#include "modules.h"

INCLUDE_BIN(_msvcirtDllData, EMBED_PATH)

extern const wibo::ModuleStub lib_msvcirt = {
	.names =
		(const char *[]){
			"msvcirt",
			nullptr,
		},
	.dllData = INCLUDE_BIN_SPAN(_msvcirtDllData),
};
