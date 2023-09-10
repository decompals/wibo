#include "common.h"

typedef void (*_PVFV)();
typedef int (*_PIFV)();

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
	DEBUG_LOG("STUB: _set_fmode(%i)\n", mode);
	return 0;
}

int *WIN_ENTRY __p__commode() { return &_commode; }

int WIN_ENTRY _crt_atexit(void (*func)()) {
	DEBUG_LOG("STUB: _crt_atexit(%p)\n", func);
	return 0;
}

int WIN_ENTRY _configure_narrow_argv(_crt_argv_mode mode) {
	DEBUG_LOG("STUB: _configure_narrow_argv(%i)\n", mode);
	return 0;
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

char ***WIN_ENTRY __p___argv() { return &wibo::argv; }

int *WIN_ENTRY __p___argc() { return &wibo::argc; }

size_t WIN_ENTRY strlen(const char *str) { return ::strlen(str); }

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
	if (strcmp(name, "_crt_atexit") == 0)
		return (void *)crt::_crt_atexit;
	if (strcmp(name, "_configure_narrow_argv") == 0)
		return (void *)crt::_configure_narrow_argv;
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
	if (strcmp(name, "__p___argv") == 0)
		return (void *)crt::__p___argv;
	if (strcmp(name, "__p___argc") == 0)
		return (void *)crt::__p___argc;
	if (strcmp(name, "strlen") == 0)
		return (void *)crt::strlen;
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
		nullptr,
	},
	resolveByName,
	nullptr,
};
