#include "macros.h"
#include "modules.h"

INCLUDE_BIN(_msvcr90DllData, EMBED_PATH)

extern const wibo::ModuleStub lib_msvcr90 = {
	.names =
		(const char *[]){
			"msvcr90",
			"msvcr80",
			nullptr,
		},
	.dllData = INCLUDE_BIN_SPAN(_msvcr90DllData),
};
