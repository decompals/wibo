#include "common.h"
#include <clocale>
#include <cstdlib>
#include <cwchar>
#include <cwctype>
#include <stdlib.h>
#include <string>
#include "strutil.h"

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

	char* WIN_ENTRY setlocale(int category, const char *locale){
		return std::setlocale(category, locale);
	}

	int WIN_ENTRY _wdupenv_s(wchar_t **buffer, size_t *numberOfElements, const wchar_t *varname){
		std::string var_str = wideStringToString((const unsigned short*)varname, wcslen(varname));
		DEBUG_LOG("_wdupenv_s: %s\n", var_str.c_str());
		if(!buffer || !varname) return 22;
		*buffer = nullptr;
		if(numberOfElements) *numberOfElements = 0;

		size_t varnamelen = wcslen(varname);

		for(wchar_t** env = __winitenv; env && *env; ++env){
			wchar_t* cur = *env;
			if(wcsncmp(cur, varname, varnamelen) == 0 && cur[varnamelen] == L'='){
				wchar_t* value = cur + varnamelen + 1;
				size_t value_len = wcslen(value);

				wchar_t* copy = (wchar_t*)malloc((value_len + 1) * sizeof(wchar_t));
				if(!copy) return 12;

				std::wmemcpy(copy, value, value_len + 1);
				*buffer = copy;

				std::string value_str = wideStringToString((const unsigned short*)copy, wcslen(copy));
				DEBUG_LOG("Value: %s\n", value_str.c_str());

				if(numberOfElements) *numberOfElements = value_len + 1;
				return 0;
			}
		}

		return 0;
	}

	void* WIN_ENTRY malloc(size_t size){
		return std::malloc(size);
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
		std::string dst_str = wideStringToString((const unsigned short*)strDestination, wcslen(strDestination));
		std::string src_str = wideStringToString((const unsigned short*)strSource, wcslen(strSource));
		DEBUG_LOG("wcscat_s %s %d %s", dst_str.c_str(), numberOfElements, src_str.c_str());
		if(!strDestination || !strSource || numberOfElements == 0) return 22;

		size_t dest_len = wcslen(strDestination);
		size_t src_len = wcslen(strSource);

		if(dest_len + src_len + 1 > numberOfElements){
			if(strDestination && numberOfElements > 0) strDestination[0] = L'\0';
			return 34;
		}

		std::wcscat(strDestination, strSource);
		dst_str = wideStringToString((const unsigned short*)strDestination, wcslen(strDestination));
		DEBUG_LOG(" --> %s\n", dst_str.c_str());

		return 0;
	}

	wchar_t* WIN_ENTRY _wcsdup(const wchar_t *strSource){
		std::string src_str = wideStringToString((const unsigned short*)strSource, wcslen(strSource));
		DEBUG_LOG("_wcsdup: %s", src_str.c_str());
		if(!strSource) return nullptr;
		size_t strLen = wcslen(strSource);

		wchar_t* dup = (wchar_t*)malloc((strLen + 1) * sizeof(wchar_t));
		if(!dup) return nullptr;

		for(int i = 0; i <= strLen; i++){
			dup[i] = strSource[i];
		}

		std::string dst_str = wideStringToString((const unsigned short*)dup, wcslen(dup));
		DEBUG_LOG(" --> %s\n", dst_str.c_str());
		return dup;
	}

	void* WIN_ENTRY memset(void *s, int c, size_t n){
		return std::memset(s, c, n);
	}

	int WIN_ENTRY wcsncpy_s(wchar_t *strDest, size_t numberOfElements, const wchar_t *strSource, size_t count){
		std::string src_str = wideStringToString((const unsigned short*)strSource, wcslen(strSource));
		DEBUG_LOG("wcsncpy_s dest size %d, src str %s, src size %d", numberOfElements, src_str.c_str(), count);

		if(!strDest || !strSource || numberOfElements == 0){
			if(strDest && numberOfElements > 0) strDest[0] = L'\0';
			return 1;
		}

		if(count == (size_t)-1) count = std::wcslen(strSource);

		if(count >= numberOfElements){
			strDest[0] = L'\0';
			return 1;
		}

		std::wcsncpy(strDest, strSource, count);
		strDest[count] = L'\0';
		std::string dst_str = wideStringToString((const unsigned short*)strDest, wcslen(strDest));
		DEBUG_LOG(" --> %s\n", dst_str.c_str());
		return 0;
	}

	int WIN_ENTRY wcsncat_s(wchar_t *strDest, size_t numberOfElements, const wchar_t *strSource, size_t count){
		std::string dst_str = wideStringToString((const unsigned short*)strDest, wcslen(strDest));
		std::string src_str = wideStringToString((const unsigned short*)strSource, wcslen(strSource));
		DEBUG_LOG("wscncat_s dest str %s, dest size %d, src str %s, src size %d", dst_str.c_str(), numberOfElements, src_str.c_str(), count);
		
		if(!strDest || !strSource || numberOfElements == 0){
			if(strDest && numberOfElements > 0) strDest[0] = L'\0';
			return 1;
		}

		size_t dest_len = std::wcslen(strDest);
		size_t src_len = (count == (size_t)-1) ? std::wcslen(strSource) : wcsnlen(strSource, count);

		if(dest_len + src_len + 1 > numberOfElements){
			strDest[0] = L'\0';
			return 1;
		}

		std::wcsncat(strDest, strSource, src_len);
		dst_str = wideStringToString((const unsigned short*)strDest, wcslen(strDest));
		DEBUG_LOG(" --> %s\n", dst_str.c_str());
		return 0;
	}

	int WIN_ENTRY _itow_s(int value, wchar_t *buffer, size_t size, int radix){
		DEBUG_LOG("STUB: _itow_s\n");
		return 0;
	}

	int WIN_ENTRY _wtoi(const wchar_t* str) {
		DEBUG_LOG("_wtoi\n");
		return (int)wcstol(str, nullptr, 10);
	}

	int WIN_ENTRY wcscpy_s(wchar_t *dest, size_t dest_size, const wchar_t *src){
		DEBUG_LOG("STUB: wcscpy_s\n");
		return 0;
	}

	int* WIN_ENTRY _get_osfhandle(int fd){
		DEBUG_LOG("STUB: _get_osfhandle %d\n", fd);
		return (int*)fd;
	}

	int WIN_ENTRY _write(int fd, const void* buffer, unsigned int count) {
		return (int)write(fd, buffer, count);
	}

	void WIN_ENTRY exit(int status){
		_Exit(status);
	}

	int WIN_ENTRY wcsncmp(const wchar_t *string1, const wchar_t *string2, size_t count){
		return std::wcsncmp(string1, string2, count);
	}

	int WIN_ENTRY _vswprintf_c_l(wchar_t* buffer, size_t size, const wchar_t* format, va_list args) {
		if (!buffer || !format || size == 0)
			return -1;
		return vswprintf(buffer, size, format, args);
	}

	const wchar_t* WIN_ENTRY wcsstr( const wchar_t *dest, const wchar_t *src ){
		return std::wcsstr(dest, src);
	}

	int WIN_ENTRY iswspace(wint_t w){
		return std::iswspace(w);
	}

	const wchar_t* WIN_ENTRY wcsrchr(const wchar_t *str, wchar_t c){
		return std::wcsrchr(str, c);
	}

	unsigned long WIN_ENTRY wcstoul(const wchar_t *strSource, wchar_t **endptr, int base){
		return std::wcstoul(strSource, endptr, base);
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
	if (strcmp(name, "malloc") == 0) return (void*)msvcrt::malloc;
	if (strcmp(name, "free") == 0) return (void*)msvcrt::free;
	if (strcmp(name, "_get_wpgmptr") == 0) return (void*)msvcrt::_get_wpgmptr;
	if (strcmp(name, "_wsplitpath_s") == 0) return (void*)msvcrt::_wsplitpath_s;
	if (strcmp(name, "wcscat_s") == 0) return (void*)msvcrt::wcscat_s;
	if (strcmp(name, "_wcsdup") == 0) return (void*)msvcrt::_wcsdup;
	if (strcmp(name, "memset") == 0) return (void*)msvcrt::memset;
	if (strcmp(name, "wcsncpy_s") == 0) return (void*)msvcrt::wcsncpy_s;
	if (strcmp(name, "wcsncat_s") == 0) return (void*)msvcrt::wcsncat_s;
	if (strcmp(name, "_itow_s") == 0) return (void*)msvcrt::_itow_s;
	if (strcmp(name, "_wtoi") == 0) return (void*)msvcrt::_wtoi;
	if (strcmp(name, "wcscpy_s") == 0) return (void*)msvcrt::wcscpy_s;
	if (strcmp(name, "_get_osfhandle") == 0) return (void*)msvcrt::_get_osfhandle;
	if (strcmp(name, "_write") == 0) return (void*)msvcrt::_write;
	if (strcmp(name, "exit") == 0) return (void*)msvcrt::exit;
	if (strcmp(name, "wcsncmp") == 0) return (void*)msvcrt::wcsncmp;
	if (strcmp(name, "_vswprintf_c_l") == 0) return (void*)msvcrt::_vswprintf_c_l;
	if (strcmp(name, "wcsstr") == 0) return (void*)msvcrt::wcsstr;
	if (strcmp(name, "iswspace") == 0) return (void*)msvcrt::iswspace;
	if (strcmp(name, "wcsrchr") == 0) return (void*)msvcrt::wcsrchr;
	if (strcmp(name, "wcstoul") == 0) return (void*)msvcrt::wcstoul;
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
