#include "macros.h"
#include "modules.h"

INCLUDE_BIN(_msvcr120DllData, EMBED_PATH)

extern const wibo::ModuleStub lib_msvcr120 = {
	.names =
		(const char *[]){
			"msvcr120",
			"msvcr110",
			nullptr,
		},
	.dllData = INCLUDE_BIN_SPAN(_msvcr120DllData),
};
