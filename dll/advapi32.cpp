#include "modules.h"

#include "advapi32_trampolines.h"

extern const wibo::ModuleStub lib_advapi32 = {
	(const char *[]){
		"advapi32",
		nullptr,
	},
	advapi32ThunkByName,
	nullptr,
};
