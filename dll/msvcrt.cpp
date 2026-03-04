#include "macros.h"
#include "modules.h"

INCLUDE_BIN(_msvcrtDllData, EMBED_PATH)

extern const wibo::ModuleStub lib_msvcrt = {
	.names =
		(const char *[]){
			"msvcrt",
			nullptr,
		},
	.dllData = INCLUDE_BIN_SPAN(_msvcrtDllData),
};
