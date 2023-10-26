#include "common.h"

typedef void (WIN_ENTRY *_PVFV)(void);

namespace msvcrt {
	int _commode;
	int _fmode;
	char **___initenv;
	char **__pgmptr;

	// Stub because we're only ever a console application
	void WIN_ENTRY __set_app_type(int at) {
	}

	int* WIN_ENTRY __p__fmode() {
		return &_fmode;
	}

	int* WIN_ENTRY __p__commode() {
		return &_commode;
	}

	char*** WIN_ENTRY __p___initenv(void) { return &___initenv; }
	char **WIN_ENTRY __p__pgmptr(void) { return __pgmptr; }
	void* WIN_ENTRY __p__iob(void) { return nullptr; }


	unsigned int WIN_ENTRY _controlfp(unsigned int _new, unsigned int mask) {
		return 0;
	}

	void WIN_ENTRY _initterm(_PVFV *start, _PVFV *end) {
		_PVFV* it = start;

		while (it < end) {
			if (*it != nullptr) {
				(**it)();
			}
			it++;
		}
	}

	int WIN_ENTRY __getmainargs(int *argc, char ***argv, char ***envp, int expand_wildcards, int *new_mode) {
		DEBUG_LOG("msvcrt::__getmainargs(%p, %p, %p, %d, %p)\n", argc, argv, envp, expand_wildcards, new_mode);
		return 0;
	}
	void WIN_ENTRY setbuf(FILE* file, char *buf) {}
}


static void *resolveByName(const char *name) {
	if (strcmp(name, "__set_app_type") == 0) return (void *) msvcrt::__set_app_type;
	if (strcmp(name, "__p__fmode") == 0) return (void *) msvcrt::__p__fmode;
	if (strcmp(name, "__p__commode") == 0) return (void *) msvcrt::__p__commode;
	if (strcmp(name, "__p___initenv") == 0) return (void *) msvcrt::__p___initenv;
	if (strcmp(name, "__p__pgmptr") == 0) return (void *) msvcrt::__p__pgmptr;
	if (strcmp(name, "__p__iob") == 0) return (void *) msvcrt::__p__iob;
	if (strcmp(name, "_controlfp") == 0) return (void *) msvcrt::_controlfp;
	if (strcmp(name, "_initterm") == 0) return (void *) msvcrt::_initterm;
	if (strcmp(name, "__getmainargs") == 0) return (void *) msvcrt::__getmainargs;
	if (strcmp(name, "setbuf") == 0) return (void *) msvcrt::setbuf;
	if (strcmp(name, "getenv") == 0) return (void *) getenv;
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
		nullptr,
	},
	resolveByName,
	nullptr,
};
