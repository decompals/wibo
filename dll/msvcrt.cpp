#include "macros.h"
#include "modules.h"

INCLUDE_BIN(_msvcrtDllData, EMBED_PATH)

extern const wibo::ModuleStub lib_msvcrt = {
	.names =
		(const char *[]){
			"msvcrt",
			"msvcrt40",
			"msvcr70",
			"msvcr71",
			"msvcr80",
			"msvcr90",
			"msvcr100",
			"msvcr110",
			"msvcr120",
			"msvcr130",
			"msvcr140",
			"ucrtbase",
			nullptr,
		},
	.dllData = INCLUDE_BIN_SPAN(_msvcrtDllData),
};
