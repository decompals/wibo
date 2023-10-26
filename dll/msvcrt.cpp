#include "common.h"
#include "files.h"

#include <string>
#include <filesystem>
#include <spawn.h>

// from https://codebrowser.dev/glibc/glibc/sysdeps/x86/fpu_control.h.html
#define _FPU_GETCW(cw) __asm__ __volatile__ ("fnstcw %0" : "=m" (*&cw))
#define _FPU_SETCW(cw) __asm__ __volatile__ ("fldcw %0" : : "m" (*&cw))

namespace msvcrt {
	int _commode;
	int _fmode;

	int fpcntrl;

	char **__initenv = NULL;

	int mb_cur_max;

	unsigned short int *pctype = NULL;
	int __errno;

	// Stub because we're only ever a console application
	void WIN_FUNC __set_app_type(int at) {
	}

	int* WIN_FUNC __p__fmode() {
		return &_fmode;
	}

	int* WIN_FUNC __p__commode() {
		return &_commode;
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

	unsigned int WIN_ENTRY _controlfp(unsigned int new_value, unsigned int mask) {
		DEBUG_LOG("_controlfp called with value: 0x%X, mask: 0x%X\n", new_value, mask);

		_FPU_GETCW(fpcntrl);
		fpcntrl = ((fpcntrl & ~mask) | (new_value & mask));
		_FPU_SETCW(fpcntrl);

		return fpcntrl;
	}

	void WIN_ENTRY _initterm(void*, void*) {
		 // do nothing
	}

	// _startupinfo*
	int WIN_ENTRY __getmainargs(int* argc, char*** argv, char*** env, int doWildCard, void* startInfo) {
		DEBUG_LOG("__getmainargs: %p, %p, %p, %i, %p\n", argc, argv, env, doWildCard, startInfo);
		*argc = wibo::argc;
		*argv = wibo::argv;

		return 0; // success
}

	char ***WIN_ENTRY __p___initenv() {
	  return &__initenv;
	}

	FILE* WIN_ENTRY __p__iob(void) {
		return 0;
	}

	void WIN_ENTRY setbuf(FILE *stream, char *buffer) {

	}

	char** WIN_ENTRY __p__pgmptr(void) {
		return (char**)malloc(1000000);
	}

	void WIN_ENTRY _splitpath(const char *c_path, char *drive, char *dir, char *fname, char *ext) {
		DEBUG_LOG("_splitpath, path: %s, %p %p %p %p\n", c_path, drive, dir, fname,	ext);
		// std::string str_path = std::string(c_path);

		if (drive) {
			// Drive letter, followed by a colon (:).
			// You can pass NULL for this parameter if you don't need the drive letter.
			strcpy(drive, "C:");
		}
		if (dir) {
			// Directory path, including trailing slash. Forward slashes ( / ), backslashes ( \ ), or both may be used.
			// You can pass NULL for this parameter if you don't need the directory path.
			strcpy(drive, "/");
		}
		if (fname) {
			// Base filename (no extension).
			// You can pass NULL for this parameter if you don't need the filename.
			strcpy(fname, "test");
		}
		if (ext) {
			// Filename extension, including leading period (.).
			// You can pass NULL for this parameter if you don't need the filename extension.
			strcpy(ext, ".c");
		}
	}

	int WIN_ENTRY _access(const char* path, int mode) {
		DEBUG_LOG("_access, path: %s, mode: %i\n", path, mode);

		// 0 = existence
		// 2 = write-only
		// 4 = read-only
		// 6 = readowrite

		return 0; // hope for the best
	}

	int WIN_ENTRY _ismbcgraph(unsigned int c) {
		// Returns nonzero if and only if c is a single-byte representation of any ASCII or katakana printable character except a white space.
		return 0;
	}
	int WIN_ENTRY _ismbcspace(unsigned int c) {
		// Returns nonzero if and only if c is a white-space character: c=0x20 or 0x09<=c<=0x0D.
		return c == 0x20 || 0x09 <= c || c <= 0x0D;
	}

	unsigned char* WIN_ENTRY _mbsinc(unsigned char* current) {
		// DEBUG_LOG("_mbsinc\n");
		// The _mbsinc function returns a pointer to the first byte of the multibyte character that immediately follows current.
		return current + 1;
	}

	void WIN_ENTRY _mbccpy(unsigned char* dest, const unsigned char* src) {
		// uhoh
		// DEBUG_LOG("_mbccpy\n");
		strcpy((char*)dest, (char*)src);
	}

	unsigned char* WIN_ENTRY _mbsdec(unsigned char* start, unsigned char* current) {
		// DEBUG_LOG("_mbsdec\n");
		// The _mbsdec function returns a pointer to the first byte of the multibyte character that immediately precedes current in the string that contains start.
		return start - 1;
	}

	void WIN_ENTRY _makepath(char* path, char* drive, char* dir, char* fname, char *ext) {
		DEBUG_LOG("_makepath: drive:%s, dir:%s fname:%s, ext:%s\n", drive, dir, fname, ext);
		strcpy(path, "test.c");
	}

	int* WIN_ENTRY __p___mb_cur_max(void) {
		DEBUG_LOG("__p___mb_cur_max\n");
		return &mb_cur_max;
	}

	unsigned short ** WIN_ENTRY __p__pctype() {
		DEBUG_LOG("__p__pctype\n");
		if (pctype == NULL) {
			pctype = (short unsigned int*)malloc(4);
		}
		return &pctype;
	}

	int* WIN_ENTRY _errno() {
		return &__errno;
	}



}


static void *resolveByName(const char *name) {
	if (strcmp(name, "__set_app_type") == 0) return (void *) msvcrt::__set_app_type;
	if (strcmp(name, "__p__fmode") == 0) return (void *) msvcrt::__p__fmode;
	if (strcmp(name, "__p__commode") == 0) return (void *) msvcrt::__p__commode;

	if (strcmp(name, "_spawnvp") == 0) return (void *) msvcrt::_spawnvp;
	if (strcmp(name, "_controlfp") == 0) return (void *) msvcrt::_controlfp;
	if (strcmp(name, "_initterm") == 0) return (void *) msvcrt::_initterm;
	if (strcmp(name, "__getmainargs") == 0) return (void *) msvcrt::__getmainargs;
	if (strcmp(name, "__p___initenv") == 0) return (void *) msvcrt::__p___initenv;
	if (strcmp(name, "__p__iob") == 0) return (void *) msvcrt::__p__iob;
	if (strcmp(name, "setbuf") == 0) return (void *) msvcrt::setbuf;
	if (strcmp(name, "__p__pgmptr") == 0) return (void *) msvcrt::__p__pgmptr;
	if (strcmp(name, "_splitpath") == 0) return (void *) msvcrt::_splitpath;
	if (strcmp(name, "_access") == 0) return (void *) msvcrt::_access;
	if (strcmp(name, "_ismbcgraph") == 0) return (void *) msvcrt::_ismbcgraph;
	if (strcmp(name, "_ismbcspace") == 0) return (void *) msvcrt::_ismbcspace;

	if (strcmp(name, "__p___mb_cur_max") == 0) return (void *) msvcrt::__p___mb_cur_max;
	if (strcmp(name, "__p__pctype") == 0) return (void *) msvcrt::__p__pctype;

	if (strcmp(name, "_mbsinc") == 0) return (void *) msvcrt::_mbsinc;
	if (strcmp(name, "_mbccpy") == 0) return (void *) msvcrt::_mbccpy;
	if (strcmp(name, "_mbsdec") == 0) return (void *) msvcrt::_mbsdec;

	if (strcmp(name, "_mbsstr") == 0) return (void *) strstr;
	if (strcmp(name, "_mbschr") == 0) return (void *) strchr;
	if (strcmp(name, "_mbsncmp") == 0) return (void *) strncmp;
	if (strcmp(name, "_mbclen") == 0) return (void *) strlen; // FIXME

	if (strcmp(name, "_dup2") == 0) return (void *) dup;
	if (strcmp(name, "_mktemp") == 0) return (void *) mktemp;
	if (strcmp(name, "_strdup") == 0) return (void *) strdup;
	if (strcmp(name, "_stricmp") == 0) return (void *) strcmp;
	if (strcmp(name, "_unlink") == 0) return (void *) unlink;
	if (strcmp(name, "_write") == 0) return (void *) write;
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
	if (strcmp(name, "strchr") == 0) return (void *) strchr;
	if (strcmp(name, "strcmp") == 0) return (void *) strcmp;
	if (strcmp(name, "strcpy") == 0) return (void *) strcpy;
	if (strcmp(name, "strlen") == 0) return (void *) strlen;
	if (strcmp(name, "strncpy") == 0) return (void *) strncpy;
	if (strcmp(name, "strtoul") == 0) return (void *) strtoul;

	if (strcmp(name, "_putenv") == 0) return (void *) putenv;
	if (strcmp(name, "_flushall") == 0) return (void *) fflush;

	if (strcmp(name, "_errno") == 0) return (void *) msvcrt::_errno;
	if (strcmp(name, "_makepath") == 0) return (void *) msvcrt::_makepath;

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
