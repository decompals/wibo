#include "common.h"
#include <cstdlib>
#include <cwchar>
#include <stdlib.h>

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
	
	// wgetmainargs references:
	// https://github.com/reactos/reactos/blob/fade0c3b8977d43f3a9e0b8887d18afcabd8e145/sdk/lib/crt/misc/getargs.c#L328
	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/getmainargs-wgetmainargs?view=msvc-170

	int WIN_FUNC __wgetmainargs(int* wargc, wchar_t*** wargv, wchar_t*** wenv, int doWildcard, int* startInfo){
		// get the regular, non-wide versions of argc/argv/env
		// argc: the number of args in argv. always >= 1
		// argv: array of null-terminated strings for command-line args.
		//		argv[0] = the command to invoke the program
		//		argv[1] = the first command-line arg
		//		argv[argc - 1] = the last command-line arg
		//		argv[argc] = NULL
		// env: array of strings for user's environment variables. always terminated by NULL entry.
		int* regular_argc = &wibo::argc;
		char*** regular_argv = &wibo::argv;
		char** regular_env = environ;

		int argc = *regular_argc;
		char** argv = *regular_argv;
		char** env = regular_env;

		DEBUG_LOG("Wildcard: %d\n", doWildcard);
		if(startInfo){
			DEBUG_LOG("Start info: %d\n", *startInfo);
		}

		std::setlocale(LC_ALL, "");

		std::vector<wchar_t*> wArgs;
		for(int i = 0; i < argc; i++){
			const char* cur_arg = argv[i];
			size_t wSize = strlen(cur_arg) + 1;
			wchar_t* wStr = new wchar_t[wSize];
			size_t result = std::mbstowcs(wStr, cur_arg, wSize);
			if(result != (size_t)-1){
				wArgs.push_back(wStr);
			}	
			else {
				DEBUG_LOG("Bad argv[%d]: %s\n", i, cur_arg);
			}
		}
		wArgs.push_back(nullptr);

		std::vector<wchar_t*> wEnvs;
		if(env){
			for(int i = 0; env[i] != nullptr; i++){
				const char* cur_env = env[i];
				size_t wSize = strlen(cur_env) + 1;
				wchar_t* wStr = new wchar_t[wSize];
				size_t result = std::mbstowcs(wStr, cur_env, wSize);
				if(result != (size_t)-1){
					wEnvs.push_back(wStr);
				}	
				else {
					DEBUG_LOG("Bad env[%d]: %s\n", i, cur_env);
				}
			}
			wEnvs.push_back(nullptr);
		}

		if(wargc) *wargc = argc;
		if(wargv) *wargv = wArgs.data();
		if(wenv) *wenv = wEnvs.data();

		return 0;
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
	if (strcmp(name, "__wgetmainargs") == 0) return (void*)msvcrt::__wgetmainargs;
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
