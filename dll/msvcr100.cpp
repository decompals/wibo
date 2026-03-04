#include "macros.h"
#include "modules.h"

INCLUDE_BIN(_msvcr100DllData, EMBED_PATH)

extern const wibo::ModuleStub lib_msvcr100 = {
	.names =
		(const char *[]){
			"msvcr100",
			nullptr,
		},
	.dllData = INCLUDE_BIN_SPAN(_msvcr100DllData),
};
