#include "common.h"

typedef void (*_PVFV)();
typedef int (*_PIFV)();

namespace msvcrt {
	int _commode;
	int _fmode;

	// Stub because we're only ever a console application
	void WIN_ENTRY __set_app_type(int at) {
	}

	int* WIN_FUNC __p__fmode() {
		return &_fmode;
	}

	int* WIN_FUNC __p__commode() {
		return &_commode;
	}

	void WIN_FUNC _initterm(const _PVFV *ppfn, const _PVFV* end) {
		for (; ppfn < end; ppfn++) {
			_PVFV func = *ppfn;
			if (func) {
				func();
			}
		}
	}

	int WIN_FUNC _initterm_e(const _PIFV *ppfn, const _PIFV *end) {
		for (; ppfn < end; ppfn++) {
			_PIFV func = *ppfn;
			if (func) {
				int err = func();
				if (err != 0)
					return err;
			}
		}
		return 0;
	}

	int WIN_ENTRY _controlfp_s(unsigned int *currentControl, unsigned int newControl, unsigned int mask) {
		DEBUG_LOG("STUB: _controlfp_s(%p, %u, %u)\n", currentControl, newControl, mask);
		return 0;
	}

	_PIFV WIN_FUNC _onexit(_PIFV func) {
		DEBUG_LOG("STUB: _onexit(%p)\n", func);
		return func;
	}

}


static void *resolveByName(const char *name) {
	if (strcmp(name, "__set_app_type") == 0) return (void *) msvcrt::__set_app_type;
	if (strcmp(name, "_fmode") == 0) return (void *)&msvcrt::_fmode;
    if (strcmp(name, "_commode") == 0) return (void *)&msvcrt::_commode;
	if (strcmp(name, "__p__fmode") == 0) return (void *) msvcrt::__p__fmode;
	if (strcmp(name, "__p__commode") == 0) return (void *) msvcrt::__p__commode;
	if (strcmp(name, "_initterm") == 0) return (void *)msvcrt::_initterm;
	if (strcmp(name, "_initterm_e") == 0) return (void *)msvcrt::_initterm_e;
	if (strcmp(name, "_controlfp_s") == 0) return (void *)msvcrt::_controlfp_s;
	if (strcmp(name, "_onexit") == 0) return (void*)msvcrt::_onexit;
	return nullptr;
}

wibo::Module lib_msvcrt = {
	(const char *[]){
		"msvcrt",
		"msvcrt.dll",
		"msvcrt40",
		"msvcrt40.dll",
		"msvcr70",
		"msvcr70.dll",
		"msvcr100",
		"msvcr100.dll",
		nullptr,
	},
	resolveByName,
	nullptr,
};
