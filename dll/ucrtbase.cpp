#include "macros.h"
#include "modules.h"

INCLUDE_BIN(_ucrtbaseDllData, EMBED_PATH)

extern const wibo::ModuleStub lib_ucrtbase = {
	.names =
		(const char *[]){
			"ucrtbase",
			nullptr,
		},
	.dllData = INCLUDE_BIN_SPAN(_ucrtbaseDllData),
};
