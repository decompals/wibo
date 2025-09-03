#include "common.h"
#include <clocale>
#include <cstdint>
#include <cstdlib>
#include <cwchar>
#include <cwctype>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>
#include "strutil.h"

typedef void (*_PVFV)();
typedef int (*_PIFV)();

namespace msvcrt {
	int _commode;
	int _fmode;
	uint16_t** __winitenv;

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

	int WIN_ENTRY __wgetmainargs(int* wargc, uint16_t*** wargv, uint16_t*** wenv, int doWildcard, int* startInfo){
		DEBUG_LOG("__wgetmainargs\n");
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
			*wargv = new uint16_t*[argc + 1]; // allocate array of our future wstrings
			for(int i = 0; i < argc; i++){
				const char* cur_arg = argv[i];

				std::vector<uint16_t> wStr = stringToWideString(cur_arg);
				
			    // allocate a copy on the heap,
				// since wStr will go out of scope
				(*wargv)[i] = new uint16_t[wStr.size() + 1];
			    std::copy(wStr.begin(), wStr.end(), (*wargv)[i]);
			    (*wargv)[i][wStr.size()] = 0;
			}
			(*wargv)[argc] = nullptr;
		}

		if(wenv){
			int count = 0;
			for(; env[count] != nullptr; count++);
			DEBUG_LOG("Found env count %d\n", count);
			*wenv = new uint16_t*[count + 1]; // allocate array of our future wstrings
			for (int i = 0; i < count; i++) {
			    const char* cur_env = env[i];
			    DEBUG_LOG("Adding env %s\n", cur_env);

			    std::vector<uint16_t> wStr = stringToWideString(cur_env);

			    // allocate a copy on the heap,
				// since wStr will go out of scope
				(*wenv)[i] = new uint16_t[wStr.size() + 1];
			    std::copy(wStr.begin(), wStr.end(), (*wenv)[i]);
			    (*wenv)[i][wStr.size()] = 0;
			}

			(*wenv)[count] = nullptr;

			__winitenv = *wenv;
		}
		return 0;
	}

	char* WIN_ENTRY getenv(const char *varname){
		return std::getenv(varname);
	}

	char* WIN_ENTRY setlocale(int category, const char *locale){
		return std::setlocale(category, locale);
	}

	int WIN_ENTRY _wdupenv_s(uint16_t **buffer, size_t *numberOfElements, const uint16_t *varname){
		std::string var_str = wideStringToString(varname);
		DEBUG_LOG("_wdupenv_s: var name %s\n", var_str.c_str());
		if(!buffer || !varname) return 22;
		*buffer = nullptr;
		if(numberOfElements) *numberOfElements = 0;

		size_t varnamelen = wstrlen(varname);

		// DEBUG_LOG("\tSearching env vars...\n");
		for(uint16_t** env = __winitenv; env && *env; ++env){
			uint16_t* cur = *env;
			std::string cur_str = wideStringToString(cur);
			// DEBUG_LOG("\tCur env var: %s\n", cur_str.c_str());
			if(wstrncmp(cur, varname, varnamelen) == 0 && cur[varnamelen] == L'='){
				DEBUG_LOG("Found the env var %s!\n", var_str.c_str());
				uint16_t* value = cur + varnamelen + 1;
				size_t value_len = wstrlen(value);

				uint16_t* copy = (uint16_t*)malloc((value_len + 1) * sizeof(uint16_t));
				if(!copy) return 12;

				wstrncpy(copy, value, value_len + 1);
				*buffer = copy;

				if(numberOfElements) *numberOfElements = value_len + 1;
				return 0;
			}
		}

		DEBUG_LOG("Could not find env var %s\n", var_str.c_str());
		return 0;
	}

	int WIN_ENTRY _wgetenv_s(size_t* pReturnValue, uint16_t* buffer, size_t numberOfElements, const uint16_t* varname){
		std::string var_str = wideStringToString(varname);
		DEBUG_LOG("_wgetenv_s: var name %s\n", var_str.c_str());
		if(!buffer || !varname) return 22;

		size_t varnamelen = wstrlen(varname);

		for(uint16_t** env = __winitenv; env && *env; ++env){
			uint16_t* cur = *env;
			std::string cur_str = wideStringToString(cur);
			DEBUG_LOG("\tCur env var: %s\n", cur_str.c_str());
			if(wstrncmp(cur, varname, varnamelen) == 0 && cur[varnamelen] == L'='){
				uint16_t* value = cur + varnamelen + 1;
				size_t value_len = wstrlen(value);

				size_t copy_len = (value_len < numberOfElements - 1) ? value_len : numberOfElements - 1;
				wstrncpy(buffer, value, copy_len);
				buffer[copy_len] = 0;

				if(pReturnValue) *pReturnValue = value_len + 1;
				return 0;
			}
		}

		buffer[0] = 0;
		if(pReturnValue) *pReturnValue = 0;
		return 0;
	}

	void* WIN_ENTRY malloc(size_t size){
		return std::malloc(size);
	}

	void WIN_ENTRY free(void* ptr){
		std::free(ptr);
	}

	int WIN_ENTRY _get_wpgmptr(uint16_t** pValue){
		DEBUG_LOG("STUB: _get_wpgmptr(%p)\n", pValue);
		return 0;
	}

	int WIN_ENTRY _wsplitpath_s(const uint16_t * path, uint16_t * drive, size_t driveNumberOfElements, uint16_t *dir, size_t dirNumberOfElements,
		uint16_t * fname, size_t nameNumberOfElements, uint16_t * ext, size_t extNumberOfElements){

		if(!path){
			DEBUG_LOG("no path\n");
			return -1;
		}
		else {
			std::string path_str = wideStringToString(path);
			DEBUG_LOG("path: %s\n", path_str.c_str());
		}

		if(drive && driveNumberOfElements) drive[0] = L'\0';
		if(dir && dirNumberOfElements) dir[0] = L'\0';
		if(fname && nameNumberOfElements) fname[0] = L'\0';
		if(ext && extNumberOfElements) ext[0] = L'\0';

		const uint16_t *slash = wstrrchr(path, L'/');
		const uint16_t *dot = wstrrchr(path, L'.');
		const uint16_t *filename_start = slash ? slash + 1 : path;
		if (dot && dot < filename_start) dot = nullptr;

		if (dir && dirNumberOfElements && slash) {
			size_t dir_len = slash - path + 1;
			if (dir_len >= dirNumberOfElements) return -1;
			wstrncpy(dir, path, dir_len);
			dir[dir_len] = L'\0';
		}

		if (fname && nameNumberOfElements) {
			size_t fname_len = dot ? (size_t)(dot - filename_start) : wstrlen(filename_start);
			if (fname_len >= nameNumberOfElements) return -1;
			wstrncpy(fname, filename_start, fname_len);
			fname[fname_len] = L'\0';
		}

		if (ext && extNumberOfElements && dot) {
			size_t ext_len = wstrlen(dot);
			if (ext_len >= extNumberOfElements) return -1;
			wstrncpy(ext, dot, ext_len);
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

	int WIN_ENTRY wcscat_s(uint16_t *strDestination, size_t numberOfElements, const uint16_t *strSource){
		std::string dst_str = wideStringToString(strDestination);
		std::string src_str = wideStringToString(strSource);
		DEBUG_LOG("wcscat_s %s %d %s", dst_str.c_str(), numberOfElements, src_str.c_str());
		if(!strDestination || !strSource || numberOfElements == 0) return 22;

		size_t dest_len = wstrlen(strDestination);
		size_t src_len = wstrlen(strSource);

		if(dest_len + src_len + 1 > numberOfElements){
			if(strDestination && numberOfElements > 0) strDestination[0] = L'\0';
			return 34;
		}

		wstrcat(strDestination, strSource);
		dst_str = wideStringToString(strDestination);
		DEBUG_LOG(" --> %s\n", dst_str.c_str());

		return 0;
	}

	uint16_t* WIN_ENTRY _wcsdup(const uint16_t *strSource){
		// std::string src_str = wideStringToString(strSource);
		// DEBUG_LOG("_wcsdup: %s", src_str.c_str());
		if(!strSource) return nullptr;
		size_t strLen = wstrlen(strSource);

		uint16_t* dup = (uint16_t*)malloc((strLen + 1) * sizeof(uint16_t));
		if(!dup) return nullptr;

		for(size_t i = 0; i <= strLen; i++){
			dup[i] = strSource[i];
		}

		// std::string dst_str = wideStringToString(dup);
		// DEBUG_LOG(" --> %s\n", dst_str.c_str());
		return dup;
	}

	int WIN_ENTRY _waccess_s(const uint16_t* path, int mode){
		std::string str = wideStringToString(path);
		DEBUG_LOG("_waccess_s %s\n", str.c_str());
		return access(str.c_str(), mode);
	}

	void* WIN_ENTRY memset(void *s, int c, size_t n){
		return std::memset(s, c, n);
	}

	int WIN_ENTRY wcsncpy_s(uint16_t *strDest, size_t numberOfElements, const uint16_t *strSource, size_t count){
		std::string src_str = wideStringToString(strSource);
		DEBUG_LOG("wcsncpy_s dest size %d, src str %s, src size %d\n", numberOfElements, src_str.c_str(), count);

		if(!strDest || !strSource || numberOfElements == 0){
			if(strDest && numberOfElements > 0) strDest[0] = L'\0';
			return 1;
		}

		if(count == (size_t)-1) count = wstrlen(strSource);

		if(count >= numberOfElements){
			strDest[0] = L'\0';
			return 1;
		}

		wstrncpy(strDest, strSource, count);
		strDest[count] = L'\0';
		// std::string dst_str = wideStringToString(strDest);
		// DEBUG_LOG(" --> %s\n", dst_str.c_str());
		return 0;
	}

	int WIN_ENTRY wcsncat_s(uint16_t *strDest, size_t numberOfElements, const uint16_t *strSource, size_t count){
		std::string dst_str = wideStringToString(strDest);
		std::string src_str = wideStringToString(strSource);
		DEBUG_LOG("wscncat_s dest str %s, dest size %d, src str %s, src size %d", dst_str.c_str(), numberOfElements, src_str.c_str(), count);
		
		if(!strDest || !strSource || numberOfElements == 0){
			if(strDest && numberOfElements > 0) strDest[0] = L'\0';
			return 1;
		}

		size_t dest_len = wstrlen(strDest);
		size_t src_len = (count == (size_t)-1) ? wstrlen(strSource) : wstrnlen(strSource, count);

		if(dest_len + src_len + 1 > numberOfElements){
			strDest[0] = L'\0';
			return 1;
		}

		wstrncat(strDest, strSource, src_len);
		dst_str = wideStringToString(strDest);
		DEBUG_LOG(" --> %s\n", dst_str.c_str());
		return 0;
	}

	int WIN_ENTRY _itow_s(int value, uint16_t *buffer, size_t size, int radix){
		DEBUG_LOG("_itow_s value %d, size %d, radix %d\n", value, size, radix);
		if (!buffer || size == 0) return 22;
		assert(radix == 10); // only base 10 supported for now

		std::string str = std::to_string(value);
		std::vector<uint16_t> wStr = stringToWideString(str.c_str());

		if(wStr.size() + 1 > size){
			buffer[0] = 0;
			return 34;
		}

		std::copy(wStr.begin(), wStr.end(), buffer);
		buffer[wStr.size()] = 0;
		return 0;
	}

	int WIN_ENTRY _wtoi(const uint16_t* str) {
		DEBUG_LOG("_wtoi\n");
		return wstrtol(str, nullptr, 10);
	}

	int WIN_ENTRY wcscpy_s(uint16_t *dest, size_t dest_size, const uint16_t *src){
		std::string src_str = wideStringToString(src);
		DEBUG_LOG("wcscpy_s %s\n", src_str.c_str());
		if (!dest || !src || dest_size == 0) {
			return 22;
		}

		if (wstrlen(src) + 1 > dest_size) {
			dest[0] = 0;
			return 34; 
		}

		wstrcpy(dest, src);
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

	int WIN_ENTRY wcsncmp(const uint16_t *string1, const uint16_t *string2, size_t count){
		return wstrncmp(string1, string2, count);
	}

	int WIN_ENTRY _vswprintf_c_l(uint16_t* buffer, size_t size, const uint16_t* format, va_list args) {
		if (!buffer || !format || size == 0)
			return -1;
		DEBUG_LOG("STUB: _vswprintf_c_l\n");
		return 0;
		// return vswprintf(buffer, size, format, args); this doesn't work because on this architecture, wchar_t is size 4, instead of size 2
	}

	const uint16_t* WIN_ENTRY wcsstr( const uint16_t *dest, const uint16_t *src ){
		return wstrstr(dest, src);
	}

	int WIN_ENTRY iswspace(uint32_t w){
		return std::iswspace(w);
	}

	int WIN_ENTRY iswdigit(uint32_t w){
		return std::iswdigit(w);
	}

	const uint16_t* WIN_ENTRY wcschr(const uint16_t* str, uint16_t c){
		return wstrchr(str, c);
	}

	const uint16_t* WIN_ENTRY wcsrchr(const uint16_t *str, uint16_t c){
		return wstrrchr(str, c);
	}

	unsigned long WIN_ENTRY wcstoul(const uint16_t *strSource, uint16_t **endptr, int base){
		return wstrtoul(strSource, endptr, base);
	}

	int WIN_ENTRY _dup2(int fd1, int fd2){
		return dup2(fd1, fd2);
	}

	FILE* WIN_ENTRY _wfsopen(const uint16_t* filename, const uint16_t* mode, int shflag){
		if (!filename || !mode) return nullptr;
		std::string fname_str = wideStringToString(filename);
		std::string mode_str = wideStringToString(mode);
		DEBUG_LOG("_wfsopen file %s, mode %s\n", fname_str.c_str(), mode_str.c_str());

		return fopen(fname_str.c_str(), mode_str.c_str());
	}

	int WIN_ENTRY fputws(const uint16_t* str, FILE* stream){
		if(!str || !stream) return EOF;
		
		std::string fname_str = wideStringToString(str);
		DEBUG_LOG("fputws %s\n", fname_str.c_str());

		if(fputs(fname_str.c_str(), stream) < 0) return EOF;
		else return 0;
	}

	int WIN_ENTRY fclose(FILE* stream){
		return ::fclose(stream);
	}

	int WIN_ENTRY _flushall(){
		DEBUG_LOG("flushall\n");
		int count = 0;

		if (fflush(stdin) == 0) count++;
		if (fflush(stdout) == 0) count++;
		if (fflush(stderr) == 0) count++;

		return count;
	}

	int* WIN_ENTRY _errno() {
		return &errno;
	}

	intptr_t WIN_ENTRY _wspawnvp(int mode, const uint16_t* cmdname, const uint16_t* const * argv){
		std::string str_cmd = wideStringToString(cmdname);
		DEBUG_LOG("STUB: _wspawnvp %s\n", str_cmd.c_str());
		return -1;
	}

	int WIN_ENTRY _wunlink(const uint16_t *filename){
		std::string str = wideStringToString(filename);
		DEBUG_LOG("_wunlink %s\n", str.c_str());
		return unlink(str.c_str());
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
	if (strcmp(name, "iswdigit") == 0) return (void*)msvcrt::iswdigit;
	if (strcmp(name, "wcschr") == 0) return (void*)msvcrt::wcschr;
	if (strcmp(name, "getenv") == 0) return (void*)msvcrt::getenv;
	if (strcmp(name, "_wgetenv_s") == 0) return (void*)msvcrt::_wgetenv_s;
	if (strcmp(name, "_waccess_s") == 0) return (void*)msvcrt::_waccess_s;
	if (strcmp(name, "_dup2") == 0) return (void*)msvcrt::_dup2;
	if (strcmp(name, "_wfsopen") == 0) return (void*)msvcrt::_wfsopen;
	if (strcmp(name, "fputws") == 0) return (void*)msvcrt::fputws;
	if (strcmp(name, "fclose") == 0) return (void*)msvcrt::fclose;
	if (strcmp(name, "_flushall") == 0) return (void*)msvcrt::_flushall;
	if (strcmp(name, "_errno") == 0) return (void*)msvcrt::_errno;
	if (strcmp(name, "_wspawnvp") == 0) return (void*)msvcrt::_wspawnvp;
	if (strcmp(name, "_wunlink") == 0) return (void*)msvcrt::_wunlink;
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
