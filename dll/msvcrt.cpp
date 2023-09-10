#include "common.h"

namespace msvcrt {
	int _commode;
	int _fmode;

	// Stub because we're only ever a console application
	void WIN_FUNC __set_app_type(int at) {
	}

	int* WIN_FUNC __p__fmode() {
		return &_fmode;
	}

	int* WIN_FUNC __p__commode() {
		return &_commode;
	}
}


static void *resolveByName(const char *name) {
	if (strcmp(name, "__set_app_type") == 0) return (void *) msvcrt::__set_app_type;
	if (strcmp(name, "__p__fmode") == 0) return (void *) msvcrt::__p__fmode;
	if (strcmp(name, "__p__commode") == 0) return (void *) msvcrt::__p__commode;
	return nullptr;
}

wibo::Module lib_msvcrt = {
	(const char *[]){
		"msvcrt40",
		"msvcrt40.dll",
		nullptr,
	},
	resolveByName,
	nullptr,
};
