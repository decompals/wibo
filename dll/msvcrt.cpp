#include "common.h"
#include <cstdlib>
#include <cwchar>
#include <stdlib.h>
#include <string>

typedef void (*_PVFV)();
typedef int (*_PIFV)();

namespace msvcrt {
	int _commode;
	int _fmode;
	wchar_t** __winitenv;

	// Stub because we're only ever a console application
	void WIN_ENTRY __set_app_type(int at) {
	}

	int* WIN_FUNC __p__fmode() {
		return &_fmode;
	}

	int* WIN_FUNC __p__commode() {
		return &_commode;
	}

	void WIN_ENTRY _initterm(const _PVFV *ppfn, const _PVFV* end) {
		for (; ppfn < end; ppfn++) {
			_PVFV func = *ppfn;
			if (func) {
				func();
			}
		}
	}

	int WIN_ENTRY _initterm_e(const _PIFV *ppfn, const _PIFV *end) {
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

	_PIFV WIN_ENTRY _onexit(_PIFV func) {
		DEBUG_LOG("STUB: _onexit(%p)\n", func);
		return func;
	}
	
	// wgetmainargs references:
	// https://github.com/reactos/reactos/blob/fade0c3b8977d43f3a9e0b8887d18afcabd8e145/sdk/lib/crt/misc/getargs.c#L328
	// https://learn.microsoft.com/en-us/cpp/c-runtime-library/getmainargs-wgetmainargs?view=msvc-170

	int WIN_ENTRY __wgetmainargs(int* wargc, wchar_t*** wargv, wchar_t*** wenv, int doWildcard, int* startInfo){
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

		if(wargc) *wargc = argc;

		std::setlocale(LC_CTYPE, "");

		if(wargv){
			*wargv = new wchar_t*[argc + 1]; // allocate array of our future wstrings
			for(int i = 0; i < argc; i++){
				const char* cur_arg = argv[i];
				size_t wSize = std::mbstowcs(nullptr, cur_arg, 0);
				if(wSize != (size_t)-1){
					wSize++; // for null terminator
					wchar_t* wStr = new wchar_t[wSize];
					std::mbstowcs(wStr, cur_arg, wSize);
					(*wargv)[i] = wStr;
				}
				else {
					DEBUG_LOG("Bad argv[%d]: %s\n", i, cur_arg);
					return -1;
				}
			}
			(*wargv)[argc] = nullptr;

			// sanity check
			// for (int i = 0; i < argc; i++) {
			// 	wchar_t* warg = (*wargv)[i];
			// 	size_t len = std::wcstombs(nullptr, warg, 0);
			// 	if (len != (size_t)-1) {
			// 		char* converted = new char[len + 1];
			// 		std::wcstombs(converted, warg, len + 1);
			// 		DEBUG_LOG("Input argv[%d]: %s\n", i, argv[i]);
			// 		DEBUG_LOG("Output wargv[%d]: %s\n", i, converted);
			// 		delete[] converted;
			// 	} else {
			// 		DEBUG_LOG("Bad wide arg conversion for %d!\n", i);
			// 	}
			// }
		}

		if(wenv){
			int count = 0;
			for(; env[count] != nullptr; count++);
			DEBUG_LOG("Found env count %d\n", count);
			*wenv = new wchar_t*[count + 1]; // allocate array of our future wstrings
			for(int i = 0; i < count; i++){
				const char* cur_env = env[i];
				size_t wSize = std::mbstowcs(nullptr, cur_env, 0);
				if(wSize != (size_t)-1){
					wSize++; // for null terminator
					wchar_t* wStr = new wchar_t[wSize];
					std::mbstowcs(wStr, cur_env, wSize);
					(*wenv)[i] = wStr;
				}
				else {
					DEBUG_LOG("Bad env[%d]: %s\n", i, cur_env);
					return -1;
				}
			}
			(*wenv)[count] = nullptr;

			// sanity check
			// for (int i = 0; i < count; i++) {
			// 	wchar_t* warg = (*wenv)[i];
			// 	size_t len = std::wcstombs(nullptr, warg, 0);
			// 	if (len != (size_t)-1) {
			// 		char* converted = new char[len + 1];
			// 		std::wcstombs(converted, warg, len + 1);
			// 		DEBUG_LOG("Input env[%d]: %s\n", i, env[i]);
			// 		DEBUG_LOG("Output wenv[%d]: %s\n", i, converted);
			// 		delete[] converted;
			// 	} else {
			// 		DEBUG_LOG("Bad wide arg conversion for %d!\n", i);
			// 	}
			// }

			__winitenv = *wenv;
		}
		return 0;
	}

	char WIN_ENTRY *setlocale(int category, const char *locale){
		DEBUG_LOG("STUB: setlocale(%d, %s)\n", category, locale);
		return (char*)"C";
	}

	int WIN_ENTRY _wdupenv_s(wchar_t **buffer, size_t *numberOfElements, const wchar_t *varname){
		if(!buffer || !varname) return -1;
		if(numberOfElements) *numberOfElements = 0;

		size_t varnamelen = wcslen(varname);

		for(wchar_t** env = __winitenv; env && *env; ++env){
			wchar_t* cur = *env;
			if(wcsncmp(cur, varname, varnamelen) == 0 && cur[varnamelen] == L'='){
				wchar_t* value = cur + varnamelen + 1;
				size_t value_len = wcslen(value);

				*buffer = (wchar_t*)malloc((value_len + 1) * sizeof(wchar_t));
				if(!*buffer) return -1;

				for(int i = 0; i <= value_len; i++){
					(*buffer)[i] = value[i];
				}

				// wscspy(*buffer, value); // y u no work
				if(numberOfElements) *numberOfElements = value_len + 1;
				return 0;
			}
		}

		return 0;
	}

	void WIN_ENTRY free(void* ptr){
		std::free(ptr);
	}

	int WIN_ENTRY _get_wpgmptr(wchar_t** pValue){
		DEBUG_LOG("STUB: _get_wpgmptr(%p)\n", pValue);
		return 0;
	}

	int WIN_ENTRY _wsplitpath_s(const wchar_t * path, wchar_t * drive, size_t driveNumberOfElements, wchar_t *dir, size_t dirNumberOfElements,
		wchar_t * fname, size_t nameNumberOfElements, wchar_t * ext, size_t extNumberOfElements){

		if(!path){
			DEBUG_LOG("no path\n");
			return -1;
		}

		{
			size_t wlen = std::wcstombs(nullptr, path, 0);
			if(wlen != (size_t)-1){
				char* converted = new char[wlen + 1];
				std::wcstombs(converted, path, wlen + 1);
				DEBUG_LOG("Path: %s\n", converted);
				delete [] converted;
			}
			else {
				DEBUG_LOG("Bad wide arg conversion for path!\n");
			}
		}

		if(drive && driveNumberOfElements) drive[0] = L'\0';
		if(dir && dirNumberOfElements) dir[0] = L'\0';
		if(fname && nameNumberOfElements) fname[0] = L'\0';
		if(ext && extNumberOfElements) ext[0] = L'\0';

		const wchar_t *slash = wcsrchr(path, L'/');
		const wchar_t *dot = wcsrchr(path, L'.');
		const wchar_t *filename_start = slash ? slash + 1 : path;
		if (dot && dot < filename_start) dot = nullptr;

		if (dir && dirNumberOfElements && slash) {
			size_t dir_len = slash - path + 1;
			if (dir_len >= dirNumberOfElements) return -1;
			wcsncpy(dir, path, dir_len);
			dir[dir_len] = L'\0';
		}

		if (fname && nameNumberOfElements) {
			size_t fname_len = dot ? (size_t)(dot - filename_start) : wcslen(filename_start);
			if (fname_len >= nameNumberOfElements) return -1;
			wcsncpy(fname, filename_start, fname_len);
			fname[fname_len] = L'\0';
		}

		if (ext && extNumberOfElements && dot) {
			size_t ext_len = wcslen(dot);
			if (ext_len >= extNumberOfElements) return -1;
			wcsncpy(ext, dot, ext_len);
			ext[ext_len] = L'\0';
		}

		if (drive && driveNumberOfElements && path[1] == L':' && path[2] == L'/') {
			if (driveNumberOfElements < 3) return -1;
			drive[0] = path[0];
			drive[1] = L':';
			drive[2] = L'\0';
		}

		return 0;
	}

	int WIN_ENTRY wcscat_s(wchar_t *strDestination, size_t numberOfElements, const wchar_t *strSource){
		if(!strDestination || !strSource || numberOfElements == 0) return -1;

		size_t dest_len = wcslen(strDestination);
		size_t src_len = wcslen(strSource);

		if(dest_len + src_len >= numberOfElements) return -1;

		for(int i = 0; i <= src_len; i++){
			strDestination[dest_len + i] = strSource[i];
		}

		return 0;
	}

	wchar_t* WIN_ENTRY _wcsdup(const wchar_t *strSource){
		if(!strSource) return nullptr;
		size_t strLen = wcslen(strSource);

		wchar_t* dup = (wchar_t*)malloc((strLen + 1) * sizeof(wchar_t));

		for(int i = 0; i <= strLen; i++){
			dup[i] = strSource[i];
		}

		return dup;
	}

	void* WIN_ENTRY memset(void *s, int c, size_t n){
		return std::memset(s, c, n);
	}

	int WIN_ENTRY wcsncpy_s(wchar_t *strDest, size_t numberOfElements, const wchar_t *strSource, size_t count){
		DEBUG_LOG("STUB: wcsncpy_s\n");
		return 0;
	}

	int WIN_ENTRY wcsncat_s(wchar_t *strDest, size_t numberOfElements, const wchar_t *strSource, size_t count){
		DEBUG_LOG("STUB: wscncat_s\n");
		return 0;
	}

}


static void *resolveByName(const char *name) {
	if (strcmp(name, "__set_app_type") == 0) return (void *) msvcrt::__set_app_type;
	if (strcmp(name, "_fmode") == 0) return (void *)&msvcrt::_fmode;
    if (strcmp(name, "_commode") == 0) return (void *)&msvcrt::_commode;
	if (strcmp(name, "__winitenv") == 0) return (void *)&msvcrt::__winitenv;
	if (strcmp(name, "__p__fmode") == 0) return (void *) msvcrt::__p__fmode;
	if (strcmp(name, "__p__commode") == 0) return (void *) msvcrt::__p__commode;
	if (strcmp(name, "_initterm") == 0) return (void *)msvcrt::_initterm;
	if (strcmp(name, "_initterm_e") == 0) return (void *)msvcrt::_initterm_e;
	if (strcmp(name, "_controlfp_s") == 0) return (void *)msvcrt::_controlfp_s;
	if (strcmp(name, "_onexit") == 0) return (void*)msvcrt::_onexit;
	if (strcmp(name, "__wgetmainargs") == 0) return (void*)msvcrt::__wgetmainargs;
	if (strcmp(name, "setlocale") == 0) return (void*)msvcrt::setlocale;
	if (strcmp(name, "_wdupenv_s") == 0) return (void*)msvcrt::_wdupenv_s;
	if (strcmp(name, "free") == 0) return (void*)msvcrt::free;
	if (strcmp(name, "_get_wpgmptr") == 0) return (void*)msvcrt::_get_wpgmptr;
	if (strcmp(name, "_wsplitpath_s") == 0) return (void*)msvcrt::_wsplitpath_s;
	if (strcmp(name, "wcscat_s") == 0) return (void*)msvcrt::wcscat_s;
	if (strcmp(name, "_wcsdup") == 0) return (void*)msvcrt::_wcsdup;
	if (strcmp(name, "memset") == 0) return (void*)msvcrt::memset;
	if (strcmp(name, "wcsncpy_s") == 0) return (void*)msvcrt::wcsncpy_s;
	if (strcmp(name, "wcsncat_s") == 0) return (void*)msvcrt::wcsncat_s;
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
