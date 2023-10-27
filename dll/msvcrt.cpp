#include "common.h"

#include <spawn.h>

// from https://codebrowser.dev/glibc/glibc/sysdeps/x86/fpu_control.h.html
#define _FPU_GETCW(cw) __asm__ __volatile__ ("fnstcw %0" : "=m" (*&cw))
#define _FPU_SETCW(cw) __asm__ __volatile__ ("fldcw %0" : : "m" (*&cw))

typedef void (WIN_ENTRY *_PVFV)(void);

namespace msvcrt {
	int _commode;
	int _fmode;

	int fpcntrl;

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

	char*** WIN_ENTRY __p___initenv(void) {
		return &___initenv;
	}

	char **WIN_ENTRY __p__pgmptr(void) {
		if (!__pgmptr) {
			__pgmptr = (char**)malloc(1000000);
			// TODO put something in here?
		}
		return __pgmptr;
	}

	FILE* WIN_ENTRY __p__iob(void) {
		return nullptr;
	}

	unsigned int WIN_ENTRY _controlfp(unsigned int new_value, unsigned int mask) {
		DEBUG_LOG("_controlfp called with value: 0x%X, mask: 0x%X\n", new_value, mask);

		_FPU_GETCW(fpcntrl);
		fpcntrl = ((fpcntrl & ~mask) | (new_value & mask));
		_FPU_SETCW(fpcntrl);

		return fpcntrl;
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

	int WIN_ENTRY __getmainargs(int* argc, char*** argv, char*** env, int doWildCard, void* startInfo) {
		DEBUG_LOG("__getmainargs: %p, %p, %p, %i, %p\n", argc, argv, env, doWildCard, startInfo);
		*argc = wibo::argc;
		*argv = wibo::argv;

		return 0; // success
	}

	void WIN_ENTRY setbuf(FILE* file, char *buf) {

	}

	int WIN_ENTRY _spawnvp(int mode, char* cmdname, char** argv) {
		DEBUG_LOG("_spawnvp: %s\n", cmdname);

		setenv("WIBO_DEBUG_INDENT", std::to_string(wibo::debugIndent + 1).c_str(), true);

		char *new_argv[]  = {cmdname};

		pid_t pid;
		if (posix_spawn(&pid, wibo::executableName, NULL, NULL, new_argv, environ)) {
			return 0;
		};

		return 1;
	}
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
	if (strcmp(name, "_spawnvp") == 0) return (void *) msvcrt::_spawnvp;

	const char* (*wibo_strchr)(const char* str, int c) = strchr;

	// 1:1 mappings with linux funcs
	if (strcmp(name, "exit") == 0) return (void *) exit;
	if (strcmp(name, "fopen") == 0) return (void *) fopen;
	if (strcmp(name, "fclose") == 0) return (void *) fclose;
	if (strcmp(name, "free") == 0) return (void *) free;
	if (strcmp(name, "getenv") == 0) return (void *) getenv;
	if (strcmp(name, "malloc") == 0) return (void *) malloc;
	if (strcmp(name, "memcpy") == 0) return (void *) memcpy;
	if (strcmp(name, "memmove") == 0) return (void *) memmove;
	if (strcmp(name, "memset") == 0) return (void *) memset;
	if (strcmp(name, "strcat") == 0) return (void *) strcat;
	if (strcmp(name, "strchr") == 0) return (void *) wibo_strchr;
	if (strcmp(name, "strcmp") == 0) return (void *) strcmp;
	if (strcmp(name, "strncmp") == 0) return (void *) strncmp;
	if (strcmp(name, "strcpy") == 0) return (void *) strcpy;
	if (strcmp(name, "strlen") == 0) return (void *) strlen;
	if (strcmp(name, "strncpy") == 0) return (void *) strncpy;
	if (strcmp(name, "strtoul") == 0) return (void *) strtoul;
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
		"msvcr71",
		"msvcr71.dll",
		nullptr,
	},
	resolveByName,
	nullptr,
};
