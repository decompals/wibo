#include "macros.h"
#include "modules.h"

INCLUDE_BIN(_mspdbDllData, EMBED_PATH)

extern const wibo::ModuleStub lib_mspdb = {
	.names =
		(const char *[]){
			"mspdbxx",
			"mspdb100",
			"mspdb80",
			nullptr,
		},
	.dllData = INCLUDE_BIN_SPAN(_mspdbDllData),
};
