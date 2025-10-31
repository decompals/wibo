#pragma once

#include "types.h"
#include <cstdint>

using TIME_T = int;
using WINT_T = unsigned short;

typedef void (_CC_CDECL *_PVFV)();
typedef int (_CC_CDECL *_PIFV)();
using _onexit_t = _PIFV;

struct _utimbuf {
	long actime;
	long modtime;
};

struct _timeb {
	TIME_T time;
	unsigned short millitm;
	short timezone;
	short dstflag;
};

typedef void (_CC_CDECL *signal_handler)(int);
using FILE = struct _IO_FILE;

struct IOBProxy {
	char *_ptr;
	int _cnt;
	char *_base;
	int _flag;
	int _file;
	int _charbuf;
	int _bufsiz;
	char *_tmpfname;
};

struct lconv;

namespace msvcrt {

IOBProxy *CDECL __iob_func();
IOBProxy *CDECL __p__iob();
void CDECL setbuf(FILE *stream, char *buffer);
void CDECL _splitpath(const char *path, char *drive, char *dir, char *fname, char *ext);
int CDECL _fileno(FILE *stream);
int CDECL _getmbcp();
unsigned int *CDECL __p___mb_cur_max();
int CDECL _setmbcp(int codepage);
unsigned char *CDECL __p__mbctype();
unsigned short **CDECL __p__pctype();
int CDECL _isctype(int ch, int mask);
void CDECL __set_app_type(int at);
int *CDECL __p__fmode();
int *CDECL __p__commode();
void CDECL _initterm(const _PVFV *ppfn, const _PVFV *end);
int CDECL _initterm_e(const _PIFV *ppfn, const _PIFV *end);
unsigned int CDECL _controlfp(unsigned int newControl, unsigned int mask);
int CDECL _controlfp_s(unsigned int *currentControl, unsigned int newControl, unsigned int mask);
_PIFV CDECL _onexit(_PIFV func);
int CDECL __wgetmainargs(int *wargc, uint16_t ***wargv, uint16_t ***wenv, int doWildcard, int *startInfo);
int CDECL __getmainargs(int *argc, char ***argv, char ***env, int doWildcard, int *startInfo);
char *CDECL getenv(const char *varname);
char ***CDECL __p___initenv();
char *CDECL strcat(char *dest, const char *src);
char *CDECL strcpy(char *dest, const char *src);
int CDECL _access(const char *path, int mode);
int CDECL _ismbblead(unsigned int c);
int CDECL _ismbbtrail(unsigned int c);
int CDECL _ismbcspace(unsigned int c);
void CDECL _mbccpy(unsigned char *dest, const unsigned char *src);
unsigned char *CDECL _mbsinc(const unsigned char *str);
unsigned char *CDECL _mbsdec(const unsigned char *start, const unsigned char *current);
unsigned int CDECL _mbclen(const unsigned char *str);
int CDECL _mbscmp(const unsigned char *lhs, const unsigned char *rhs);
int CDECL _mbsicmp(const unsigned char *lhs, const unsigned char *rhs);
unsigned char *CDECL _mbsstr(const unsigned char *haystack, const unsigned char *needle);
unsigned char *CDECL _mbschr(const unsigned char *str, unsigned int ch);
unsigned char *CDECL _mbsrchr(const unsigned char *str, unsigned int ch);
unsigned char *CDECL _mbslwr(unsigned char *str);
unsigned char *CDECL _mbsupr(unsigned char *str);
unsigned char *CDECL _mbsinc_l(const unsigned char *str, void *);
unsigned char *CDECL _mbsdec_l(const unsigned char *start, const unsigned char *current, void *locale);
int CDECL _mbsncmp(const unsigned char *lhs, const unsigned char *rhs, SIZE_T count);
SIZE_T CDECL _mbsspn(const unsigned char *str, const unsigned char *set);
int CDECL _ismbcdigit(unsigned int ch);
int CDECL _stricmp(const char *lhs, const char *rhs);
int CDECL _strnicmp(const char *lhs, const char *rhs, SIZE_T count);
int CDECL _memicmp(const void *lhs, const void *rhs, SIZE_T count);
int CDECL _vsnprintf(char *buffer, SIZE_T count, const char *format, va_list args);
int CDECL_NO_CONV _snprintf(char *buffer, SIZE_T count, const char *format, ...);
int CDECL_NO_CONV sprintf(char *buffer, const char *format, ...);
int CDECL_NO_CONV printf(const char *format, ...);
int CDECL_NO_CONV sscanf(const char *buffer, const char *format, ...);
char *CDECL fgets(char *str, int count, FILE *stream);
SIZE_T CDECL fread(void *buffer, SIZE_T size, SIZE_T count, FILE *stream);
FILE *CDECL _fsopen(const char *filename, const char *mode, int shflag);
int CDECL _sopen(const char *path, int oflag, int shflag, int pmode);
int CDECL _read(int fd, void *buffer, unsigned int count);
int CDECL _close(int fd);
long CDECL _lseek(int fd, long offset, int origin);
int CDECL _unlink(const char *path);
int CDECL _utime(const char *path, const _utimbuf *times);
int CDECL _chsize(int fd, long size);
char *CDECL strncpy(char *dest, const char *src, SIZE_T count);
char *CDECL strpbrk(const char *str, const char *accept);
char *CDECL strstr(const char *haystack, const char *needle);
char *CDECL strrchr(const char *str, int ch);
char *CDECL strtok(char *str, const char *delim);
long CDECL _adj_fdiv_r(long value);
void CDECL _adjust_fdiv(long n);
int CDECL _ftime(struct _timeb *timeptr);
unsigned long CDECL _ultoa(unsigned long value, char *str, int radix);
char *CDECL _ltoa(long value, char *str, int radix);
char *CDECL _makepath(char *path, const char *drive, const char *dir, const char *fname, const char *ext);
char *CDECL _fullpath(char *absPath, const char *relPath, SIZE_T maxLength);
int CDECL _putenv(const char *envString);
char *CDECL _mktemp(char *templateName);
int CDECL _except_handler3(void *record, void *frame, void *context, void *dispatch);
int CDECL getchar();
TIME_T CDECL time(TIME_T *t);
char *CDECL __unDName(char *outputString, const char *mangledName, int maxStringLength, void *(*allocFunc)(SIZE_T),
					  void (*freeFunc)(void *), unsigned short);
char *CDECL setlocale(int category, const char *locale);
int CDECL _wdupenv_s(uint16_t **buffer, SIZE_T *numberOfElements, const uint16_t *varname);
int CDECL _wgetenv_s(SIZE_T *pReturnValue, uint16_t *buffer, SIZE_T numberOfElements, const uint16_t *varname);
SIZE_T CDECL strlen(const char *str);
int CDECL strcmp(const char *lhs, const char *rhs);
int CDECL strncmp(const char *lhs, const char *rhs, SIZE_T count);
void CDECL _exit(int status);
int CDECL strcpy_s(char *dest, SIZE_T dest_size, const char *src);
int CDECL strcat_s(char *dest, SIZE_T numberOfElements, const char *src);
int CDECL strncpy_s(char *dest, SIZE_T dest_size, const char *src, SIZE_T count);
char *CDECL _strdup(const char *strSource);
unsigned long CDECL strtoul(const char *str, char **endptr, int base);
void *CDECL malloc(SIZE_T size);
void *CDECL calloc(SIZE_T count, SIZE_T size);
void *CDECL realloc(void *ptr, SIZE_T size);
void *CDECL _malloc_crt(SIZE_T size);
void CDECL _lock(int locknum);
void CDECL _unlock(int locknum);
_onexit_t CDECL __dllonexit(_onexit_t func, _PVFV **pbegin, _PVFV **pend);
void CDECL free(void *ptr);
void *CDECL memcpy(void *dest, const void *src, SIZE_T count);
void *CDECL memmove(void *dest, const void *src, SIZE_T count);
int CDECL memcmp(const void *lhs, const void *rhs, SIZE_T count);
void CDECL qsort(void *base, SIZE_T num, SIZE_T size, int (*compar)(const void *, const void *));
int CDECL fflush(FILE *stream);
int CDECL vfwprintf(FILE *stream, const uint16_t *format, va_list args);
FILE *CDECL fopen(const char *filename, const char *mode);
int CDECL _dup2(int fd1, int fd2);
int CDECL _isatty(int fd);
int CDECL fseek(FILE *stream, long offset, int origin);
long CDECL ftell(FILE *stream);
int CDECL feof(FILE *stream);
int CDECL fputws(const uint16_t *str, FILE *stream);
int CDECL _cputws(const uint16_t *string);
uint16_t *CDECL fgetws(uint16_t *buffer, int size, FILE *stream);
WINT_T CDECL fgetwc(FILE *stream);
int CDECL _wfopen_s(FILE **stream, const uint16_t *filename, const uint16_t *mode);
int CDECL _wcsicmp(const uint16_t *lhs, const uint16_t *rhs);
int CDECL _wmakepath_s(uint16_t *path, SIZE_T sizeInWords, const uint16_t *drive, const uint16_t *dir,
					   const uint16_t *fname, const uint16_t *ext);
int CDECL _wputenv_s(const uint16_t *varname, const uint16_t *value);
unsigned long CDECL wcsspn(const uint16_t *str1, const uint16_t *str2);
long CDECL _wtol(const uint16_t *str);
int CDECL _wcsupr_s(uint16_t *str, SIZE_T size);
int CDECL _wcslwr_s(uint16_t *str, SIZE_T size);
WINT_T CDECL towlower(WINT_T ch);
unsigned int CDECL _mbctolower(unsigned int ch);
int CDECL toupper(int ch);
int CDECL tolower(int ch);
int CDECL _ftime64_s(void *timeb);
int CDECL _crt_debugger_hook(int value);
int CDECL _configthreadlocale(int mode);
void CDECL __setusermatherr(void *handler);
void CDECL _cexit();
int CDECL vfprintf(FILE *stream, const char *format, va_list args);
int CDECL_NO_CONV fprintf(FILE *stream, const char *format, ...);
int CDECL fputc(int ch, FILE *stream);
SIZE_T CDECL fwrite(const void *buffer, SIZE_T size, SIZE_T count, FILE *stream);
char *CDECL strerror(int errnum);
char *CDECL strchr(const char *str, int character);
struct lconv *CDECL localeconv();
signal_handler CDECL signal(int sig, signal_handler handler);
SIZE_T CDECL wcslen(const uint16_t *str);
void CDECL abort();
int CDECL atoi(const char *str);
int CDECL _amsg_exit(int reason);
void CDECL _invoke_watson(const uint16_t *, const uint16_t *, const uint16_t *, unsigned int, uintptr_t);
void CDECL terminateShim();
int CDECL _purecall();
int CDECL _except_handler4_common(void *, void *, void *, void *);
long CDECL _XcptFilter(unsigned long code, void *);
int CDECL _get_wpgmptr(uint16_t **pValue);
char **CDECL __p__pgmptr();
int CDECL _wsplitpath_s(const uint16_t *path, uint16_t *drive, SIZE_T driveNumberOfElements, uint16_t *dir,
						SIZE_T dirNumberOfElements, uint16_t *fname, SIZE_T nameNumberOfElements, uint16_t *ext,
						SIZE_T extNumberOfElements);
int CDECL wcscat_s(uint16_t *strDestination, SIZE_T numberOfElements, const uint16_t *strSource);
uint16_t *CDECL _wcsdup(const uint16_t *strSource);
int CDECL _waccess_s(const uint16_t *path, int mode);
void *CDECL memset(void *s, int c, SIZE_T n);
int CDECL wcsncpy_s(uint16_t *strDest, SIZE_T numberOfElements, const uint16_t *strSource, SIZE_T count);
int CDECL wcsncat_s(uint16_t *strDest, SIZE_T numberOfElements, const uint16_t *strSource, SIZE_T count);
int CDECL _itow_s(int value, uint16_t *buffer, SIZE_T size, int radix);
int CDECL _wtoi(const uint16_t *str);
int CDECL _ltoa_s(long value, char *buffer, SIZE_T sizeInChars, int radix);
int CDECL wcscpy_s(uint16_t *dest, SIZE_T dest_size, const uint16_t *src);
int CDECL_NO_CONV swprintf_s(uint16_t *buffer, SIZE_T sizeOfBuffer, const uint16_t *format, ...);
int CDECL_NO_CONV swscanf_s(const uint16_t *buffer, const uint16_t *format, ...);
int *CDECL _get_osfhandle(int fd);
int CDECL _write(int fd, const void *buffer, unsigned int count);
void CDECL exit(int status);
int CDECL wcsncmp(const uint16_t *string1, const uint16_t *string2, SIZE_T count);
int CDECL_NO_CONV _vswprintf_c_l(uint16_t *buffer, SIZE_T size, const uint16_t *format, ...);
const uint16_t *CDECL wcsstr(const uint16_t *dest, const uint16_t *src);
int CDECL iswspace(uint32_t w);
int CDECL iswdigit(uint32_t w);
const uint16_t *CDECL wcschr(const uint16_t *str, uint16_t c);
const uint16_t *CDECL wcsrchr(const uint16_t *str, uint16_t c);
unsigned long CDECL wcstoul(const uint16_t *strSource, uint16_t **endptr, int base);
FILE *CDECL _wfsopen(const uint16_t *filename, const uint16_t *mode, int shflag);
int CDECL puts(const char *str);
int CDECL fclose(FILE *stream);
int CDECL _flushall();
int *CDECL _errno();
intptr_t CDECL _wspawnvp(int mode, const uint16_t *cmdname, const uint16_t *const *argv);
intptr_t CDECL _spawnvp(int mode, const char *cmdname, const char *const *argv);
int CDECL _wunlink(const uint16_t *filename);
uint16_t *CDECL _wfullpath(uint16_t *absPath, const uint16_t *relPath, SIZE_T maxLength);

} // namespace msvcrt
