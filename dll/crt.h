#pragma once

#include "types.h"

typedef void(_CC_CDECL *_PVFV)();
typedef int(_CC_CDECL *_PIFV)();
typedef void(_CC_CDECL *_invalid_parameter_handler)(const WCHAR *, const WCHAR *, const WCHAR *, UINT, UINT_PTR);

typedef enum _crt_app_type {
	_crt_unknown_app,
	_crt_console_app,
	_crt_gui_app,
} _crt_app_type;

typedef enum _crt_argv_mode {
	_crt_argv_no_arguments,
	_crt_argv_unexpanded_arguments,
	_crt_argv_expanded_arguments,
} _crt_argv_mode;

typedef void(_CC_CDECL *signal_handler)(int);
typedef int(_CC_CDECL *sort_compare)(const void *, const void *);
typedef int(_CC_CDECL *_onexit_t)();

struct _onexit_table_t {
	_onexit_t *first;
	_onexit_t *last;
	_onexit_t *end;
};

namespace crt {

extern int _commode;
extern int _fmode;

void CDECL _initterm(const _PVFV *ppfn, const _PVFV *end);
int CDECL _initterm_e(const _PIFV *ppfn, const _PIFV *end);
void CDECL _set_app_type(_crt_app_type type);
int CDECL _set_fmode(int mode);
int *CDECL __p__commode();
int *CDECL __p__fmode();
int CDECL _crt_atexit(void (*func)());
int CDECL _configure_narrow_argv(_crt_argv_mode mode);
_invalid_parameter_handler CDECL _set_invalid_parameter_handler(_invalid_parameter_handler newHandler);
int CDECL _controlfp_s(unsigned int *currentControl, unsigned int newControl, unsigned int mask);
int CDECL _configthreadlocale(int per_thread_locale_type);
int CDECL _initialize_narrow_environment();
int CDECL _set_new_mode(int newhandlermode);
char **CDECL _get_initial_narrow_environment();
char ***CDECL __p__environ();
char ***CDECL __p___argv();
int *CDECL __p___argc();
SIZE_T CDECL strlen(const char *str);
int CDECL strcmp(const char *lhs, const char *rhs);
int CDECL strncmp(const char *lhs, const char *rhs, SIZE_T count);
char *CDECL strcpy(char *dest, const char *src);
char *CDECL strncpy(char *dest, const char *src, SIZE_T count);
const char *CDECL strrchr(const char *str, int ch);
void *CDECL malloc(SIZE_T size);
void *CDECL calloc(SIZE_T count, SIZE_T size);
void *CDECL realloc(void *ptr, SIZE_T newSize);
void CDECL free(void *ptr);
void *CDECL memcpy(void *dest, const void *src, SIZE_T count);
void *CDECL memmove(void *dest, const void *src, SIZE_T count);
void *CDECL memset(void *dest, int ch, SIZE_T count);
int CDECL memcmp(const void *lhs, const void *rhs, SIZE_T count);
int CDECL __setusermatherr(void *handler);
int CDECL _initialize_onexit_table(_onexit_table_t *table);
int CDECL _register_onexit_function(_onexit_table_t *table, _onexit_t func);
int CDECL _execute_onexit_table(_onexit_table_t *table);
void CDECL exit(int status);
void CDECL _cexit();
void CDECL _exit(int status);
void CDECL abort();
signal_handler CDECL signal(int signum, signal_handler handler);
void *CDECL __acrt_iob_func(unsigned int index);
int CDECL_NO_CONV __stdio_common_vfprintf(unsigned long long options, _FILE *stream, const char *format, void *locale,
										  va_list args);
int CDECL_NO_CONV __stdio_common_vsprintf(unsigned long long options, char *buffer, SIZE_T len, const char *format,
										  void *locale, va_list args);
void CDECL qsort(void *base, SIZE_T num, SIZE_T size, sort_compare compare);
int CDECL puts(const char *str);

} // namespace crt
