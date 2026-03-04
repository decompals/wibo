#include "macros.h"
#include "modules.h"

INCLUDE_BIN(_msvcr71DllData, EMBED_PATH)

extern const wibo::ModuleStub lib_msvcr71 = {
	.names =
		(const char *[]){
			"msvcr71",
			"msvcr70",
			nullptr,
		},
	.dllData = INCLUDE_BIN_SPAN(_msvcr71DllData),
};
