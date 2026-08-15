#include "macros.h"
#include "modules.h"

INCLUDE_BIN(_msvcrt20DllData, EMBED_PATH)

extern const wibo::ModuleStub lib_msvcrt20 = {
	.names =
		(const char *[]){
			"msvcrt20",
			nullptr,
		},
	.dllData = INCLUDE_BIN_SPAN(_msvcrt20DllData),
};
