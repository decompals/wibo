#include "macros.h"
#include "modules.h"

INCLUDE_BIN(_msvcrt40DllData, EMBED_PATH)

extern const wibo::ModuleStub lib_msvcrt40 = {
	.names =
		(const char *[]){
			"msvcrt40",
			nullptr,
		},
	.dllData = INCLUDE_BIN_SPAN(_msvcrt40DllData),
};
