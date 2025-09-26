#include "common.h"

#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <unistd.h>

typedef void (*_PVFV)();
typedef int (*_PIFV)();
typedef void (*_invalid_parameter_handler)(const wchar_t *, const wchar_t *, const wchar_t *, unsigned int, uintptr_t);

extern char **environ;

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

namespace crt {

int _commode = 0;
int _fmode = 0;

std::vector<_PVFV> atexitFuncs;
_invalid_parameter_handler invalidParameterHandler = nullptr;

void WIN_ENTRY _initterm(const _PVFV *ppfn, const _PVFV *end) {
	do {
		if (_PVFV pfn = *++ppfn) {
			pfn();
		}
	} while (ppfn < end);
}

int WIN_ENTRY _initterm_e(const _PIFV *ppfn, const _PIFV *end) {
	do {
		if (_PIFV pfn = *++ppfn) {
			if (int err = pfn())
				return err;
		}
	} while (ppfn < end);

	return 0;
}

void WIN_ENTRY _set_app_type(_crt_app_type type) { DEBUG_LOG("STUB: _set_app_type(%i)\n", type); }

int WIN_ENTRY _set_fmode(int mode) {
	DEBUG_LOG("_set_fmode(%i)\n", mode);
	_fmode = mode;
	return 0;
}

int *WIN_ENTRY __p__commode() { return &_commode; }

int *WIN_ENTRY __p__fmode() { return &_fmode; }

int WIN_ENTRY _crt_atexit(void (*func)()) {
	DEBUG_LOG("_crt_atexit(%p)\n", func);
	atexitFuncs.push_back(func);
	return 0;
}

int WIN_ENTRY _configure_narrow_argv(_crt_argv_mode mode) {
	DEBUG_LOG("STUB: _configure_narrow_argv(%i)\n", mode);
	return 0;
}

_invalid_parameter_handler WIN_ENTRY _set_invalid_parameter_handler(_invalid_parameter_handler newHandler) {
	DEBUG_LOG("STUB: _set_invalid_parameter_handler(%p)\n", newHandler);
	_invalid_parameter_handler oldHandler = invalidParameterHandler;
	invalidParameterHandler = newHandler;
	return oldHandler;
}

int WIN_ENTRY _controlfp_s(unsigned int *currentControl, unsigned int newControl, unsigned int mask) {
	DEBUG_LOG("STUB: _controlfp_s(%p, %u, %u)\n", currentControl, newControl, mask);
	return 0;
}

int WIN_ENTRY _configthreadlocale(int per_thread_locale_type) {
	DEBUG_LOG("STUB: _configthreadlocale(%i)\n", per_thread_locale_type);
	return 0;
}

int WIN_ENTRY _initialize_narrow_environment() {
	DEBUG_LOG("STUB: _initialize_narrow_environment()\n");
	return 0;
}

int WIN_ENTRY _set_new_mode(int newhandlermode) {
	DEBUG_LOG("STUB: _set_new_mode(%i)\n", newhandlermode);
	return 0;
}

char **WIN_ENTRY _get_initial_narrow_environment() { return environ; }

char ***WIN_ENTRY __p__environ() { return &environ; }

char ***WIN_ENTRY __p___argv() { return &wibo::argv; }

int *WIN_ENTRY __p___argc() { return &wibo::argc; }

size_t WIN_ENTRY strlen(const char *str) { return ::strlen(str); }

int WIN_ENTRY strncmp(const char *lhs, const char *rhs, size_t count) { return ::strncmp(lhs, rhs, count); }

void *WIN_ENTRY malloc(size_t size) { return ::malloc(size); }

void *WIN_ENTRY calloc(size_t count, size_t size) { return ::calloc(count, size); }

void *WIN_ENTRY realloc(void *ptr, size_t newSize) { return ::realloc(ptr, newSize); }

void WIN_ENTRY free(void *ptr) { ::free(ptr); }

void *WIN_ENTRY memcpy(void *dest, const void *src, size_t count) { return std::memcpy(dest, src, count); }

int WIN_ENTRY __setusermatherr(void *handler) {
	DEBUG_LOG("STUB: __setusermatherr(%p)\n", handler);
	return 0;
}

int WIN_ENTRY _initialize_onexit_table(void *table) {
	DEBUG_LOG("STUB: _initialize_onexit_table(%p)\n", table);
	wibo::registerOnExitTable(table);
	return 0;
}

int WIN_ENTRY _register_onexit_function(void *table, void (*func)()) {
	DEBUG_LOG("STUB: _register_onexit_function(%p, %p)\n", table, func);
	wibo::addOnExitFunction(table, func);
	return 0;
}

int WIN_ENTRY _execute_onexit_table(void *table) {
	DEBUG_LOG("STUB: _execute_onexit_table(%p)\n", table);
	wibo::executeOnExitTable(table);
	return 0;
}

void WIN_ENTRY exit(int status) {
	DEBUG_LOG("exit(%i)\n", status);
	for (auto it = atexitFuncs.rbegin(); it != atexitFuncs.rend(); ++it) {
		DEBUG_LOG("Calling atexit function %p\n", *it);
		(*it)();
	}
	::exit(status);
}

void WIN_ENTRY _cexit(void) {
	DEBUG_LOG("_cexit()\n");
	for (auto it = atexitFuncs.rbegin(); it != atexitFuncs.rend(); ++it) {
		DEBUG_LOG("Calling atexit function %p\n", *it);
		(*it)();
	}
}

void WIN_ENTRY _exit(int status) {
	DEBUG_LOG("_exit(%i)\n", status);
	::_exit(status);
}

void WIN_ENTRY abort(void) {
	DEBUG_LOG("abort()\n");
	std::abort();
}

using signal_handler = void (*)(int);

signal_handler WIN_ENTRY signal(int signum, signal_handler handler) { return std::signal(signum, handler); }

void *WIN_ENTRY __acrt_iob_func(unsigned int index) {
	if (index == 0)
		return stdin;
	if (index == 1)
		return stdout;
	if (index == 2)
		return stderr;
	return nullptr;
}

int WIN_ENTRY __stdio_common_vfprintf(unsigned long long /*options*/, FILE *stream, const char *format, void * /*locale*/, va_list args) {
	return vfprintf(stream, format, args);
}

} // namespace crt

static void *resolveByName(const char *name) {
	if (strcmp(name, "_initterm") == 0)
		return (void *)crt::_initterm;
	if (strcmp(name, "_initterm_e") == 0)
		return (void *)crt::_initterm_e;
	if (strcmp(name, "_set_app_type") == 0)
		return (void *)crt::_set_app_type;
	if (strcmp(name, "_set_fmode") == 0)
		return (void *)crt::_set_fmode;
	if (strcmp(name, "__p__commode") == 0)
		return (void *)crt::__p__commode;
	if (strcmp(name, "__p__fmode") == 0)
		return (void *)crt::__p__fmode;
	if (strcmp(name, "_crt_atexit") == 0)
		return (void *)crt::_crt_atexit;
	if (strcmp(name, "_configure_narrow_argv") == 0)
		return (void *)crt::_configure_narrow_argv;
	if (strcmp(name, "_set_invalid_parameter_handler") == 0)
		return (void *)crt::_set_invalid_parameter_handler;
	if (strcmp(name, "_controlfp_s") == 0)
		return (void *)crt::_controlfp_s;
	if (strcmp(name, "_configthreadlocale") == 0)
		return (void *)crt::_configthreadlocale;
	if (strcmp(name, "_initialize_narrow_environment") == 0)
		return (void *)crt::_initialize_narrow_environment;
	if (strcmp(name, "_set_new_mode") == 0)
		return (void *)crt::_set_new_mode;
	if (strcmp(name, "_get_initial_narrow_environment") == 0)
		return (void *)crt::_get_initial_narrow_environment;
	if (strcmp(name, "__p__environ") == 0)
		return (void *)crt::__p__environ;
	if (strcmp(name, "__p___argv") == 0)
		return (void *)crt::__p___argv;
	if (strcmp(name, "__p___argc") == 0)
		return (void *)crt::__p___argc;
	if (strcmp(name, "strlen") == 0)
		return (void *)crt::strlen;
	if (strcmp(name, "strncmp") == 0)
		return (void *)crt::strncmp;
	if (strcmp(name, "malloc") == 0)
		return (void *)crt::malloc;
	if (strcmp(name, "calloc") == 0)
		return (void *)crt::calloc;
	if (strcmp(name, "realloc") == 0)
		return (void *)crt::realloc;
	if (strcmp(name, "free") == 0)
		return (void *)crt::free;
	if (strcmp(name, "memcpy") == 0)
		return (void *)crt::memcpy;
	if (strcmp(name, "exit") == 0)
		return (void *)crt::exit;
	if (strcmp(name, "_cexit") == 0)
		return (void *)crt::_cexit;
	if (strcmp(name, "_exit") == 0)
		return (void *)crt::_exit;
	if (strcmp(name, "abort") == 0)
		return (void *)crt::abort;
	if (strcmp(name, "signal") == 0)
		return (void *)crt::signal;
	if (strcmp(name, "__acrt_iob_func") == 0)
		return (void *)crt::__acrt_iob_func;
	if (strcmp(name, "__stdio_common_vfprintf") == 0)
		return (void *)crt::__stdio_common_vfprintf;
	if (strcmp(name, "__setusermatherr") == 0)
		return (void *)crt::__setusermatherr;
	if (strcmp(name, "_initialize_onexit_table") == 0)
		return (void *)crt::_initialize_onexit_table;
	if (strcmp(name, "_register_onexit_function") == 0)
		return (void *)crt::_register_onexit_function;
	if (strcmp(name, "_execute_onexit_table") == 0)
		return (void *)crt::_execute_onexit_table;
	return nullptr;
}

wibo::Module lib_crt = {
	(const char *[]){
		"api-ms-win-crt-heap-l1-1-0",
		"api-ms-win-crt-heap-l1-1-0.dll",
		"api-ms-win-crt-locale-l1-1-0",
		"api-ms-win-crt-locale-l1-1-0.dll",
		"api-ms-win-crt-runtime-l1-1-0",
		"api-ms-win-crt-runtime-l1-1-0.dll",
		"api-ms-win-crt-stdio-l1-1-0",
		"api-ms-win-crt-stdio-l1-1-0.dll",
		"api-ms-win-crt-string-l1-1-0",
		"api-ms-win-crt-string-l1-1-0.dll",
		"api-ms-win-crt-environment-l1-1-0",
		"api-ms-win-crt-environment-l1-1-0.dll",
		"api-ms-win-crt-math-l1-1-0",
		"api-ms-win-crt-math-l1-1-0.dll",
		"api-ms-win-crt-private-l1-1-0",
		"api-ms-win-crt-private-l1-1-0.dll",
		nullptr,
	},
	resolveByName,
	nullptr,
};
