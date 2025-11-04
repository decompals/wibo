#include "crt.h"

#include "common.h"
#include "context.h"
#include "crt_trampolines.h"
#include "heap.h"
#include "kernel32/internal.h"
#include "modules.h"

#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <vector>

namespace {

FILE *mapToHostFile(_FILE *file) {
	if (!file)
		return nullptr;
	switch (file->_file) {
	case STDIN_FILENO:
		return stdin;
	case STDOUT_FILENO:
		return stdout;
	case STDERR_FILENO:
		return stderr;
	default:
		return nullptr;
	}
}

} // namespace

namespace crt {

int _commode = 0;
int _fmode = 0;

std::vector<_PVFV> atexitFuncs;
_invalid_parameter_handler invalidParameterHandler = nullptr;

void CDECL _initterm(const _PVFV *ppfn, const _PVFV *end) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("_initterm(%p, %p)\n", ppfn, end);
	do {
		if (_PVFV pfn = *++ppfn) {
			DEBUG_LOG("-> calling %p\n", pfn);
			call__PVFV(pfn);
		}
	} while (ppfn < end);
}

int CDECL _initterm_e(const _PIFV *ppfn, const _PIFV *end) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("_initterm_e(%p, %p)\n", ppfn, end);
	do {
		if (_PIFV pfn = *++ppfn) {
			DEBUG_LOG("-> calling %p\n", pfn);
			int err = call__PIFV(pfn);
			if (err)
				return err;
		}
	} while (ppfn < end);

	return 0;
}

void CDECL _set_app_type(_crt_app_type type) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: _set_app_type(%i)\n", type);
}

int CDECL _set_fmode(int mode) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("_set_fmode(%i)\n", mode);
	_fmode = mode;
	return 0;
}

int *CDECL __p__commode() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("__p__commode()\n");
	return &_commode;
}

int *CDECL __p__fmode() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("__p__fmode()\n");
	return &_fmode;
}

int CDECL _crt_atexit(void (*func)()) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("_crt_atexit(%p)\n", func);
	atexitFuncs.push_back(func);
	return 0;
}

int CDECL _configure_narrow_argv(_crt_argv_mode mode) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: _configure_narrow_argv(%i)\n", mode);
	return 0;
}

_invalid_parameter_handler CDECL _set_invalid_parameter_handler(_invalid_parameter_handler newHandler) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: _set_invalid_parameter_handler(%p)\n", newHandler);
	_invalid_parameter_handler oldHandler = invalidParameterHandler;
	invalidParameterHandler = newHandler;
	return oldHandler;
}

int CDECL _controlfp_s(unsigned int *currentControl, unsigned int newControl, unsigned int mask) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: _controlfp_s(%p, %u, %u)\n", currentControl, newControl, mask);
	return 0;
}

int CDECL _configthreadlocale(int per_thread_locale_type) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: _configthreadlocale(%i)\n", per_thread_locale_type);
	return 0;
}

int CDECL _initialize_narrow_environment() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: _initialize_narrow_environment()\n");
	return 0;
}

int CDECL _set_new_mode(int newhandlermode) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: _set_new_mode(%i)\n", newhandlermode);
	return 0;
}

char **CDECL _get_initial_narrow_environment() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("_get_initial_narrow_environment()\n");
	return environ;
}

char ***CDECL __p__environ() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("__p__environ()\n");
	return &environ;
}

char ***CDECL __p___argv() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("__p___argv()\n");
	return &wibo::argv;
}

int *CDECL __p___argc() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("__p___argc()\n");
	return &wibo::argc;
}

SIZE_T CDECL strlen(const char *str) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("strlen(%p)\n", str);
	return ::strlen(str);
}

int CDECL strcmp(const char *lhs, const char *rhs) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("strcmp(%p, %p)\n", lhs, rhs);
	return ::strcmp(lhs, rhs);
}

int CDECL strncmp(const char *lhs, const char *rhs, SIZE_T count) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("strncmp(%p, %p, %zu)\n", lhs, rhs, count);
	return ::strncmp(lhs, rhs, count);
}

char *CDECL strcpy(char *dest, const char *src) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("strcpy(%p, %p)\n", dest, src);
	return ::strcpy(dest, src);
}

char *CDECL strncpy(char *dest, const char *src, SIZE_T count) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("strncpy(%p, %p, %zu)\n", dest, src, count);
	return ::strncpy(dest, src, count);
}

const char *CDECL strrchr(const char *str, int ch) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("strrchr(%p, %i)\n", str, ch);
	return ::strrchr(str, ch);
}

void *CDECL malloc(SIZE_T size) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("malloc(%zu)\n", size);
	return wibo::heap::guestMalloc(size);
}

void *CDECL calloc(SIZE_T count, SIZE_T size) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("calloc(%zu, %zu)\n", count, size);
	return wibo::heap::guestCalloc(count, size);
}

void *CDECL realloc(void *ptr, SIZE_T newSize) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("realloc(%p, %zu)\n", ptr, newSize);
	return wibo::heap::guestRealloc(ptr, newSize);
}

void CDECL free(void *ptr) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("free(%p)\n", ptr);
	wibo::heap::guestFree(ptr);
}

void *CDECL memcpy(void *dest, const void *src, SIZE_T count) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("memcpy(%p, %p, %zu)\n", dest, src, count);
	return std::memcpy(dest, src, count);
}

void *CDECL memmove(void *dest, const void *src, SIZE_T count) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("memmove(%p, %p, %zu)\n", dest, src, count);
	return std::memmove(dest, src, count);
}

void *CDECL memset(void *dest, int ch, SIZE_T count) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("memset(%p, %i, %zu)\n", dest, ch, count);
	return std::memset(dest, ch, count);
}

int CDECL memcmp(const void *lhs, const void *rhs, SIZE_T count) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("memcmp(%p, %p, %zu)\n", lhs, rhs, count);
	return std::memcmp(lhs, rhs, count);
}

int CDECL __setusermatherr(void *handler) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: __setusermatherr(%p)\n", handler);
	return 0;
}

int CDECL _initialize_onexit_table(_onexit_table_t *table) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("_initialize_onexit_table(%p)\n", table);
	if (!table)
		return -1;
	if (table->first != table->last)
		return 0;
	table->first = nullptr;
	table->last = nullptr;
	table->end = nullptr;
	return 0;
}

int CDECL _register_onexit_function(_onexit_table_t *table, _onexit_t func) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("_register_onexit_function(%p, %p)\n", table, func);
	if (!table || !func)
		return -1;
	if (table->last == table->end) {
		size_t count = table->end - table->first;
		size_t newCount = count + 1;
		if (newCount <= 0)
			return -1;
		_onexit_t *newTable =
			static_cast<_onexit_t *>(wibo::heap::guestRealloc(table->first, newCount * sizeof(_onexit_t)));
		if (!newTable)
			return -1;
		table->first = newTable;
		table->last = newTable + count;
		table->end = newTable + newCount;
	}
	*table->last++ = func;
	return 0;
}

int CDECL _execute_onexit_table(_onexit_table_t *table) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("_execute_onexit_table(%p)\n", table);
	if (!table)
		return -1;
	for (auto it = table->first; it != table->last; ++it) {
		DEBUG_LOG("Calling onexit_table function %p\n", *it);
		call__onexit_t(*it);
	}
	return 0;
}

void CDECL exit(int status) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("exit(%i)\n", status);
	_cexit();
	kernel32::exitInternal(status);
}

void CDECL _cexit() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("_cexit()\n");
	for (auto it = atexitFuncs.rbegin(); it != atexitFuncs.rend(); ++it) {
		DEBUG_LOG("Calling atexit function %p\n", *it);
		call__PVFV(*it);
	}
	std::fflush(nullptr);
}

void CDECL _exit(int status) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("_exit(%i)\n", status);
	kernel32::exitInternal(status);
}

void CDECL abort() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("abort()\n");
	std::abort();
}

signal_handler CDECL signal(int signum, signal_handler handler) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("signal(%i, %p)\n", signum, handler);
	return std::signal(signum, handler);
}

void *CDECL __acrt_iob_func(unsigned int index) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("__acrt_iob_func(%u)\n", index);
	if (index == 0)
		return stdin;
	if (index == 1)
		return stdout;
	if (index == 2)
		return stderr;
	return nullptr;
}

int CDECL_NO_CONV __stdio_common_vfprintf(unsigned long long options, _FILE *stream, const char *format, void *locale,
										  va_list args) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("__stdio_common_vfprintf(%llu, %p, %s, %p, %p)\n", options, stream, format, locale, args);
	FILE *hostFile = mapToHostFile(stream);
	if (!hostFile)
		return -1;
	return vfprintf(hostFile, format, args);
}

int CDECL_NO_CONV __stdio_common_vsprintf(unsigned long long options, char *buffer, SIZE_T len, const char *format,
										  void *locale, va_list args) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("__stdio_common_vsprintf(%llu, %p, %zu, %s, %p, ...)\n", options, buffer, len, format, locale);
	if (!buffer || !format)
		return -1;
	int result = vsnprintf(buffer, len, format, args);
	if (result < 0)
		return -1;
	if (len > 0 && static_cast<SIZE_T>(result) >= len)
		return -1;
	return result;
}

static thread_local sort_compare currentCompare = nullptr;

static int doCompare(const void *a, const void *b) { return call_sort_compare(currentCompare, a, b); }

void CDECL qsort(void *base, SIZE_T num, SIZE_T size, sort_compare compare) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("qsort(%p, %zu, %zu, %p)\n", base, num, size, compare);
	currentCompare = compare;
	::qsort(base, num, size, doCompare);
}

int CDECL puts(const char *str) {
	HOST_CONTEXT_GUARD();
	if (!str) {
		str = "(null)";
	}
	DEBUG_LOG("puts(%s)\n", str);
	if (std::fputs(str, stdout) < 0)
		return EOF;
	if (std::fputc('\n', stdout) == EOF)
		return EOF;
	return 0;
}

} // namespace crt

#include "crt_trampolines.h"

extern const wibo::ModuleStub lib_crt = {
	(const char *[]){
		"api-ms-win-crt-heap-l1-1-0",
		"api-ms-win-crt-locale-l1-1-0",
		"api-ms-win-crt-runtime-l1-1-0",
		"api-ms-win-crt-stdio-l1-1-0",
		"api-ms-win-crt-string-l1-1-0",
		"api-ms-win-crt-environment-l1-1-0",
		"api-ms-win-crt-math-l1-1-0",
		"api-ms-win-crt-private-l1-1-0",
		"api-ms-win-crt-utility-l1-1-0",
		nullptr,
	},
	crtThunkByName,
	nullptr,
};
