#include "common.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <clocale>
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <strings.h>
#include <type_traits>
#include <unordered_map>
#include <unistd.h>
#include <vector>
#include <spawn.h>
#include <sys/wait.h>
#include <math.h>
#include "files.h"
#include "processes.h"
#include "strutil.h"

typedef void (*_PVFV)();
typedef int (*_PIFV)();
using _onexit_t = _PIFV;

extern "C" char **environ;

namespace msvcrt {
	int _commode;
	int _fmode;
	char** __initenv;
	uint16_t** __winitenv;
	uint16_t* _wpgmptr;
	static unsigned int mbCurMaxValue = 1;

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

	using UserMathErrHandler = int (*)(struct _exception *);

	UserMathErrHandler &mathErrHandler() {
		static UserMathErrHandler handler = nullptr;
		return handler;
	}

	std::mutex &mathErrMutex() {
		static std::mutex mutex;
		return mutex;
	}

	IOBProxy *standardIobEntries() {
		static IOBProxy entries[3] = {};
		return entries;
	}

	std::unordered_map<void *, FILE *> &iobMapping() {
		static std::unordered_map<void *, FILE *> mapping;
		return mapping;
	}

	std::once_flag &iobInitFlag() {
		static std::once_flag flag;
		return flag;
	}

	void initializeIobMapping() {
		std::call_once(iobInitFlag(), []() {
			auto &mapping = iobMapping();
			IOBProxy *entries = standardIobEntries();
			mapping.emplace(static_cast<void *>(&entries[0]), stdin);
			mapping.emplace(static_cast<void *>(&entries[1]), stdout);
			mapping.emplace(static_cast<void *>(&entries[2]), stderr);
		});
	}

	FILE *mapToHostFile(FILE *stream) {
		initializeIobMapping();
		auto &mapping = iobMapping();
		auto it = mapping.find(stream);
		if (it != mapping.end()) {
			return it->second;
		}
		return stream;
	}

	void refreshMbCurMax() {
		mbCurMaxValue = static_cast<unsigned int>(MB_CUR_MAX);
	}

	namespace {
		struct DllOnExitTable {
			_PVFV **pbegin;
			_PVFV **pend;
			std::vector<_PVFV> callbacks;
			bool registered;
		};

		constexpr size_t LOCK_TABLE_SIZE = 64;
		std::array<std::recursive_mutex, LOCK_TABLE_SIZE> &lockTable() {
			static std::array<std::recursive_mutex, LOCK_TABLE_SIZE> table;
			return table;
		}

		std::vector<DllOnExitTable> &dllOnExitTables() {
			static std::vector<DllOnExitTable> tables;
			return tables;
		}

		std::mutex &dllOnExitMutex() {
			static std::mutex mutex;
			return mutex;
		}

		DllOnExitTable &ensureDllOnExitTable(_PVFV **pbegin, _PVFV **pend) {
			auto &tables = dllOnExitTables();
			for (auto &table : tables) {
				if (table.pbegin == pbegin && table.pend == pend) {
					return table;
				}
			}
			tables.push_back(DllOnExitTable{pbegin, pend, {}, false});
			return tables.back();
		}

		std::string normalizeEnvStringForWindows(const char *src) {
			if (!src) {
				return std::string();
			}
			std::string entry(src);
			auto pos = entry.find('=');
			if (pos == std::string::npos) {
				return entry;
			}
			std::string name = entry.substr(0, pos);
			std::string value = entry.substr(pos + 1);
			if (strcasecmp(name.c_str(), "PATH") == 0) {
				std::string converted = files::hostPathListToWindows(value);
				std::string result = converted.empty() ? value : converted;
				std::string exeDir;
				if (wibo::argv && wibo::argv[0]) {
					std::filesystem::path exePath = std::filesystem::absolute(std::filesystem::path(wibo::argv[0])).parent_path();
					if (!exePath.empty()) {
						exeDir = files::pathToWindows(exePath);
					}
				}
				if (!exeDir.empty()) {
					std::string loweredResult = stringToLower(result);
					std::string loweredExe = stringToLower(exeDir);
					bool present = false;
					size_t start = 0;
					while (start <= loweredResult.size()) {
						size_t end = loweredResult.find(';', start);
						if (end == std::string::npos) {
							end = loweredResult.size();
						}
						if (loweredResult.substr(start, end - start) == loweredExe) {
							present = true;
							break;
						}
						if (end == loweredResult.size()) {
							break;
						}
						start = end + 1;
					}
					if (!present) {
						if (!result.empty() && result.back() != ';') {
							result.push_back(';');
						}
						result += exeDir;
					}
				}
				entry = name + "=" + result;
			}
			return entry;
		}

		template <typename CharT>
		struct StringListStorage {
			std::vector<std::unique_ptr<CharT[]>> strings;
			std::unique_ptr<CharT*[]> pointers;

			template <typename Converter>
			CharT **assign(char **source, Converter convert) {
				if (!source) {
					strings.clear();
					pointers.reset();
					return nullptr;
				}

				size_t count = 0;
				while (source[count]) {
					++count;
				}

				strings.clear();
				strings.reserve(count);
				pointers = std::make_unique<CharT *[]>(count + 1);

				for (size_t i = 0; i < count; ++i) {
					auto data = convert(source[i]);
					auto buffer = std::make_unique<CharT[]>(data.size());
					std::copy(data.begin(), data.end(), buffer.get());
					CharT *raw = buffer.get();
					strings.emplace_back(std::move(buffer));
					pointers[i] = raw;
				}

				pointers[count] = nullptr;
				return pointers.get();
			}
		};

		std::vector<char> copyNarrowString(const char *src) {
			std::string normalized = normalizeEnvStringForWindows(src);
			size_t len = normalized.size();
			std::vector<char> result(len + 1);
			if (len > 0) {
				std::memcpy(result.data(), normalized.data(), len);
			}
			result[len] = '\0';
			return result;
		}

		std::vector<uint16_t> copyWideString(const char *src) {
			std::string normalized = normalizeEnvStringForWindows(src);
			return stringToWideString(normalized.c_str());
		}

		template <typename CharT, typename Converter>
		// NOLINTNEXTLINE(readability-non-const-parameter)
		int getMainArgsCommon(int *argcOut, CharT ***argvOut, CharT ***envOut, Converter convert) {
			if (argcOut) {
				*argcOut = wibo::argc;
			}

			static StringListStorage<CharT> argvStorage;
			static StringListStorage<CharT> envStorage;

			if (argvOut) {
				*argvOut = argvStorage.assign(wibo::argv, convert);
			}

			CharT **envData = envStorage.assign(environ, convert);
			if (envOut) {
				*envOut = envData;
			}

			if constexpr (std::is_same_v<CharT, uint16_t>) {
				__winitenv = envData;
			} else if constexpr (std::is_same_v<CharT, char>) {
				__initenv = envData;
			}

			return 0;
		}

		template <typename CharT>
		size_t envStringLength(const CharT *str) {
			if (!str) {
				return 0;
			}
			if constexpr (std::is_same_v<CharT, char>) {
				return std::strlen(str);
			} else {
				return wstrlen(str);
			}
		}

		template <typename CharT>
		int envStringCompare(const CharT *lhs, const CharT *rhs, size_t count) {
			if constexpr (std::is_same_v<CharT, char>) {
				return std::strncmp(lhs, rhs, count);
			} else {
				return wstrncmp(lhs, rhs, count);
			}
		}

		template <typename CharT>
		struct EnvLookupResult {
			const CharT *value;
			size_t length;
		};

		template <typename CharT>
		std::optional<EnvLookupResult<CharT>> findEnvironmentValue(CharT **env, const CharT *varname) {
			if (!env || !varname) {
				return std::nullopt;
			}

			size_t nameLength = envStringLength(varname);
			if (nameLength == 0) {
				return std::nullopt;
			}

			for (CharT **cursor = env; *cursor; ++cursor) {
				CharT *entry = *cursor;
				if (envStringCompare(entry, varname, nameLength) == 0 && entry[nameLength] == static_cast<CharT>('=')) {
					const CharT *value = entry + nameLength + 1;
					return EnvLookupResult<CharT>{value, envStringLength(value)};
				}
			}

			return std::nullopt;
		}

		uint16_t **ensureWideEnvironment() {
			if (!__winitenv) {
				getMainArgsCommon<uint16_t>(nullptr, nullptr, nullptr, copyWideString);
			}
			return __winitenv;
		}
	} // namespace

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
		DEBUG_LOG("_onexit(%p)\n", func);
		if(!func) return nullptr;
		if (atexit(reinterpret_cast<void (*)()>(func)) != 0) return nullptr;
		return func;
	}

	// NOLINTNEXTLINE(readability-non-const-parameter)
	int WIN_ENTRY __wgetmainargs(int *wargc, uint16_t ***wargv, uint16_t ***wenv, int doWildcard, int *startInfo) {
		DEBUG_LOG("__wgetmainargs(doWildcard=%d)\n", doWildcard);
		(void)startInfo;
		if (doWildcard) {
			DEBUG_LOG("\tWildcard expansion is not implemented\n");
		}

		std::setlocale(LC_CTYPE, "");
		return getMainArgsCommon<uint16_t>(wargc, wargv, wenv, copyWideString);
	}

	// NOLINTNEXTLINE(readability-non-const-parameter)
	int WIN_ENTRY __getmainargs(int *argc, char ***argv, char ***env, int doWildcard, int *startInfo) {
		DEBUG_LOG("__getmainargs(doWildcard=%d)\n", doWildcard);
		(void)startInfo;
		if (doWildcard) {
			DEBUG_LOG("\tWildcard expansion is not implemented\n");
		}
		return getMainArgsCommon<char>(argc, argv, env, copyNarrowString);
	}

	char* WIN_ENTRY getenv(const char *varname){
		return std::getenv(varname);
	}

char* WIN_ENTRY setlocale(int category, const char *locale){
	char *result = std::setlocale(category, locale);
	if (result) {
		refreshMbCurMax();
	}
	return result;
}

	int WIN_ENTRY _wdupenv_s(uint16_t **buffer, size_t *numberOfElements, const uint16_t *varname){
		if (buffer) {
			*buffer = nullptr;
		}
		if (numberOfElements) {
			*numberOfElements = 0;
		}

		if (!buffer || !varname) {
			DEBUG_LOG("_wdupenv_s: invalid parameter\n");
			errno = EINVAL;
			return EINVAL;
		}

		std::string var_str = wideStringToString(varname);
		DEBUG_LOG("_wdupenv_s: var name %s\n", var_str.c_str());

		auto env = ensureWideEnvironment();
		auto match = findEnvironmentValue(env, varname);
		if (!match) {
			DEBUG_LOG("Could not find env var %s\n", var_str.c_str());
			return 0;
		}

		size_t value_len = match->length;
		auto *copy = static_cast<uint16_t *>(malloc((value_len + 1) * sizeof(uint16_t)));
		if (!copy) {
			DEBUG_LOG("_wdupenv_s: allocation failed\n");
			errno = ENOMEM;
			return ENOMEM;
		}

		wstrncpy(copy, match->value, value_len);
		copy[value_len] = 0;
		*buffer = copy;
		if (numberOfElements) {
			*numberOfElements = value_len + 1;
		}
		return 0;
	}

	int WIN_ENTRY _wgetenv_s(size_t* pReturnValue, uint16_t* buffer, size_t numberOfElements, const uint16_t* varname){
		if (pReturnValue) {
			*pReturnValue = 0;
		}
		if (numberOfElements > 0 && buffer) {
			buffer[0] = 0;
		}

		bool bufferRequired = numberOfElements != 0;
		if (!pReturnValue || !varname || (bufferRequired && !buffer)) {
			DEBUG_LOG("_wgetenv_s: invalid parameter\n");
			errno = EINVAL;
			return EINVAL;
		}

		std::string var_str = wideStringToString(varname);
		DEBUG_LOG("_wgetenv_s: var name %s\n", var_str.c_str());

		auto env = ensureWideEnvironment();
		auto match = findEnvironmentValue(env, varname);
		if (!match) {
			return 0;
		}

		size_t required = match->length + 1;
		*pReturnValue = required;
		if (!bufferRequired || !buffer) {
			return 0;
		}

		if (required > numberOfElements) {
			errno = ERANGE;
			return ERANGE;
		}

		wstrncpy(buffer, match->value, match->length);
		buffer[match->length] = 0;
		return 0;
	}

	size_t WIN_ENTRY strlen(const char *str) { return ::strlen(str); }

	int WIN_ENTRY strcmp(const char *lhs, const char *rhs) { return ::strcmp(lhs, rhs); }

	int WIN_ENTRY strncmp(const char *lhs, const char *rhs, size_t count) { return ::strncmp(lhs, rhs, count); }

	void* WIN_ENTRY malloc(size_t size){
		return std::malloc(size);
	}

	void* WIN_ENTRY calloc(size_t count, size_t size){
		return std::calloc(count, size);
	}

	void* WIN_ENTRY realloc(void *ptr, size_t size) {
		return std::realloc(ptr, size);
	}

	void* WIN_ENTRY _malloc_crt(size_t size) {
		return std::malloc(size);
	}

	void WIN_ENTRY _lock(int locknum) {
		if (locknum < 0 || static_cast<size_t>(locknum) >= LOCK_TABLE_SIZE) {
			DEBUG_LOG("_lock: unsupported lock %d\n", locknum);
			return;
		}
		lockTable()[static_cast<size_t>(locknum)].lock();
	}

	void WIN_ENTRY _unlock(int locknum) {
		if (locknum < 0 || static_cast<size_t>(locknum) >= LOCK_TABLE_SIZE) {
			DEBUG_LOG("_unlock: unsupported lock %d\n", locknum);
			return;
		}
		lockTable()[static_cast<size_t>(locknum)].unlock();
	}

	_onexit_t WIN_ENTRY __dllonexit(_onexit_t func, _PVFV **pbegin, _PVFV **pend) {
		if (!pbegin || !pend) {
			return nullptr;
		}

		std::lock_guard<std::mutex> guard(dllOnExitMutex());
		auto &table = ensureDllOnExitTable(pbegin, pend);
		if (!table.registered) {
			wibo::registerOnExitTable(reinterpret_cast<void *>(pbegin));
			table.registered = true;
		}

		if (func) {
			auto callback = reinterpret_cast<_PVFV>(func);
			table.callbacks.push_back(callback);
			wibo::addOnExitFunction(reinterpret_cast<void *>(pbegin), reinterpret_cast<void (*)()>(callback));
		}

		if (table.callbacks.empty()) {
			*pbegin = nullptr;
			*pend = nullptr;
		} else {
			_PVFV *dataPtr = table.callbacks.data();
			*pbegin = dataPtr;
			*pend = dataPtr + table.callbacks.size();
		}

		return reinterpret_cast<_onexit_t>(func);
	}

	void WIN_ENTRY free(void* ptr){
		std::free(ptr);
	}

	void* WIN_ENTRY memcpy(void *dest, const void *src, size_t count) {
		return std::memcpy(dest, src, count);
	}

	void* WIN_ENTRY memmove(void *dest, const void *src, size_t count) {
		return std::memmove(dest, src, count);
	}

	int WIN_ENTRY memcmp(const void *lhs, const void *rhs, size_t count) {
		return std::memcmp(lhs, rhs, count);
	}

	int WIN_ENTRY fflush(FILE *stream) {
		return std::fflush(stream);
	}

	FILE *WIN_ENTRY fopen(const char *filename, const char *mode) {
		return std::fopen(filename, mode);
	}

	int WIN_ENTRY _dup2(int fd1, int fd2) {
		return dup2(fd1, fd2);
	}

	int WIN_ENTRY _isatty(int fd) {
		return isatty(fd);
	}

	int WIN_ENTRY fseek(FILE *stream, long offset, int origin) {
		return std::fseek(stream, offset, origin);
	}

	long WIN_ENTRY ftell(FILE *stream) {
		return std::ftell(stream);
	}

	int WIN_ENTRY feof(FILE *stream) {
		return std::feof(stream);
	}

	int WIN_ENTRY fputws(const uint16_t *str, FILE *stream) {
		std::wstring temp;
		if (str) {
			for (const uint16_t *cursor = str; *cursor; ++cursor) {
				temp.push_back(static_cast<wchar_t>(*cursor));
			}
		}
		return std::fputws(temp.c_str(), stream);
	}

	uint16_t* WIN_ENTRY fgetws(uint16_t *buffer, int size, FILE *stream) {
		if (!buffer || size <= 0) {
			return nullptr;
		}
		std::vector<wchar_t> temp(static_cast<size_t>(size));
		wchar_t *res = std::fgetws(temp.data(), size, stream);
		if (!res) {
			return nullptr;
		}
		for (int i = 0; i < size; ++i) {
			buffer[i] = static_cast<uint16_t>(temp[i]);
			if (temp[i] == L'\0') {
				break;
			}
		}
		return buffer;
	}

	wint_t WIN_ENTRY fgetwc(FILE *stream) {
		return std::fgetwc(stream);
	}

	int WIN_ENTRY _wfopen_s(FILE **stream, const uint16_t *filename, const uint16_t *mode) {
		if (!stream || !filename || !mode) {
			errno = EINVAL;
			return EINVAL;
		}
		std::string narrowName = wideStringToString(filename);
		std::string narrowMode = wideStringToString(mode);
		FILE *handle = std::fopen(narrowName.c_str(), narrowMode.c_str());
		if (!handle) {
			*stream = nullptr;
			return errno ? errno : EINVAL;
		}
		*stream = handle;
		return 0;
	}

	int WIN_ENTRY _wcsicmp(const uint16_t *lhs, const uint16_t *rhs) {
		if (lhs == rhs) {
			return 0;
		}
		if (!lhs) {
			return -1;
		}
		if (!rhs) {
			return 1;
		}

		while (*lhs && *rhs) {
			uint16_t a = wcharToLower(*lhs++);
			uint16_t b = wcharToLower(*rhs++);
			if (a != b) {
				return static_cast<int>(a) - static_cast<int>(b);
			}
		}

		uint16_t a = wcharToLower(*lhs);
		uint16_t b = wcharToLower(*rhs);
		return static_cast<int>(a) - static_cast<int>(b);
	}

	int WIN_ENTRY _wmakepath_s(uint16_t *path, size_t sizeInWords, const uint16_t *drive, const uint16_t *dir,
				 const uint16_t *fname, const uint16_t *ext) {
		if (!path || sizeInWords == 0) {
			return EINVAL;
		}

		path[0] = 0;
		std::u16string result;

		auto append = [&](const uint16_t *src) {
			if (!src || !*src) {
				return;
			}
			for (const uint16_t *cursor = src; *cursor; ++cursor) {
				result.push_back(static_cast<char16_t>(*cursor));
			}
		};

		if (drive && *drive) {
			result.push_back(static_cast<char16_t>(drive[0]));
			if (drive[1] == u':') {
				result.push_back(u':');
				append(drive + 2);
			} else {
				result.push_back(u':');
				append(drive + 1);
			}
		}

		auto appendDir = [&](const uint16_t *directory) {
			if (!directory || !*directory) {
				return;
			}
			append(directory);
			if (result.empty()) {
				return;
			}
			char16_t last = result.back();
			if (last != u'/' && last != u'\\') {
				result.push_back(u'\\');
			}
		};

		appendDir(dir);
		append(fname);

		if (ext && *ext) {
			if (*ext != u'.') {
				result.push_back(u'.');
				append(ext);
			} else {
				append(ext);
			}
		}

		size_t required = result.size() + 1;
		if (required > sizeInWords) {
			path[0] = 0;
			return ERANGE;
		}

		for (size_t i = 0; i < result.size(); ++i) {
			path[i] = static_cast<uint16_t>(result[i]);
		}
		path[result.size()] = 0;
		return 0;
	}

	int WIN_ENTRY _wputenv_s(const uint16_t *varname, const uint16_t *value) {
		if (!varname || !value) {
			errno = EINVAL;
			return EINVAL;
		}

		if (!*varname) {
			errno = EINVAL;
			return EINVAL;
		}

		for (const uint16_t *cursor = varname; *cursor; ++cursor) {
			if (*cursor == static_cast<uint16_t>('=')) {
				errno = EINVAL;
				return EINVAL;
			}
		}

		std::string name = wideStringToString(varname);
		if (name.empty()) {
			errno = EINVAL;
			return EINVAL;
		}

		int resultCode = 0;
		if (!*value) {
			if (unsetenv(name.c_str()) != 0) {
				resultCode = errno != 0 ? errno : EINVAL;
			}
		} else {
			std::string narrowValue = wideStringToString(value);
			if (setenv(name.c_str(), narrowValue.c_str(), 1) != 0) {
				resultCode = errno != 0 ? errno : EINVAL;
			}
		}

		if (resultCode != 0) {
			errno = resultCode;
			return resultCode;
		}

		getMainArgsCommon<char>(nullptr, nullptr, nullptr, copyNarrowString);
		getMainArgsCommon<uint16_t>(nullptr, nullptr, nullptr, copyWideString);
		return 0;
	}

	unsigned long WIN_ENTRY wcsspn(const uint16_t *str1, const uint16_t *str2) {
		if (!str1 || !str2) {
			return 0;
		}
		unsigned long count = 0;
		for (const uint16_t *p = str1; *p; ++p) {
			bool match = false;
			for (const uint16_t *q = str2; *q; ++q) {
				if (*p == *q) {
					match = true;
					break;
				}
			}
			if (!match) {
				break;
			}
			++count;
		}
		return count;
	}

	long WIN_ENTRY _wtol(const uint16_t *str) {
		return wstrtol(str, nullptr, 10);
	}

	int WIN_ENTRY _wcsupr_s(uint16_t *str, size_t size) {
		if (!str || size == 0) {
			return EINVAL;
		}
		size_t len = wstrnlen(str, size);
		if (len >= size) {
			return ERANGE;
		}
		for (size_t i = 0; i < len; ++i) {
			wchar_t ch = static_cast<wchar_t>(str[i]);
			str[i] = static_cast<uint16_t>(std::towupper(ch));
		}
		return 0;
	}

	int WIN_ENTRY _wcslwr_s(uint16_t *str, size_t size) {
		if (!str || size == 0) {
			return EINVAL;
		}
		size_t len = wstrnlen(str, size);
		if (len >= size) {
			return ERANGE;
		}
		for (size_t i = 0; i < len; ++i) {
			wchar_t ch = static_cast<wchar_t>(str[i]);
			str[i] = static_cast<uint16_t>(std::towlower(ch));
		}
		return 0;
	}

	wint_t WIN_ENTRY towlower(wint_t ch) {
		return static_cast<wint_t>(std::towlower(static_cast<wchar_t>(ch)));
	}

	int WIN_ENTRY _ftime64_s(void *timeb) {
		DEBUG_LOG("STUB: _ftime64_s(%p)\n", timeb);
		return 0;
	}

	int WIN_ENTRY _crt_debugger_hook(int value) {
		DEBUG_LOG("_crt_debugger_hook(%d)\n", value);
		(void)value;
		return 0;
	}

	int WIN_ENTRY _configthreadlocale(int mode) {
		static int currentMode = 0;
		int previous = currentMode;
		if (mode == -1) {
			return previous;
		}
		if (mode == 0 || mode == 1 || mode == 2) {
			currentMode = mode;
			return previous;
		}
		errno = EINVAL;
		return -1;
	}

	void WIN_ENTRY __setusermatherr(UserMathErrHandler handler) {
		std::lock_guard<std::mutex> lock(mathErrMutex());
		mathErrHandler() = handler;
	}

	void WIN_ENTRY _cexit() {
		DEBUG_LOG("_cexit()\n");
		std::fflush(nullptr);
	}

	static FILE *resolveFileStream(FILE *stream) {
		if (!stream) {
			return nullptr;
		}
		return mapToHostFile(stream);
	}

	int WIN_ENTRY vfprintf(FILE *stream, const char *format, va_list args) {
		if (!format || !stream) {
			errno = EINVAL;
			return -1;
		}
		FILE *native = resolveFileStream(stream);
		if (!native) {
			errno = EINVAL;
			return -1;
		}
		va_list argsCopy;
		va_copy(argsCopy, args);
		int result = std::vfprintf(native, format, argsCopy);
		va_end(argsCopy);
		return result;
	}

	int WIN_ENTRY fprintf(FILE *stream, const char *format, ...) {
		va_list args;
		va_start(args, format);
		int result = msvcrt::vfprintf(stream, format, args);
		va_end(args);
		return result;
	}

	int WIN_ENTRY fputc(int ch, FILE *stream) {
		if (!stream) {
			errno = EINVAL;
			return EOF;
		}
		FILE *native = resolveFileStream(stream);
		if (!native) {
			errno = EINVAL;
			return EOF;
		}
		return std::fputc(ch, native);
	}

	size_t WIN_ENTRY fwrite(const void *buffer, size_t size, size_t count, FILE *stream) {
		if (!buffer || !stream) {
			errno = EINVAL;
			return 0;
		}
		FILE *native = resolveFileStream(stream);
		if (!native) {
			errno = EINVAL;
			return 0;
		}
		return std::fwrite(buffer, size, count, native);
	}

	char *WIN_ENTRY strerror(int errnum) {
		return std::strerror(errnum);
	}

	char *WIN_ENTRY strchr(const char *str, int character) {
		return const_cast<char *>(std::strchr(str, character));
	}

	struct lconv *WIN_ENTRY localeconv() {
		return std::localeconv();
	}

	using SignalHandler = void (*)(int);

	SignalHandler WIN_ENTRY signal(int sig, SignalHandler handler) {
		return std::signal(sig, handler);
	}

	size_t WIN_ENTRY wcslen(const uint16_t *str) {
		return wstrlen(str);
	}

	static void abort_and_log(const char *reason) {
		DEBUG_LOG("Runtime abort: %s\n", reason ? reason : "");
		std::abort();
	}

	void WIN_ENTRY abort() {
		abort_and_log("abort");
	}

	int WIN_ENTRY atoi(const char *str) {
		if (!str) {
			errno = EINVAL;
			return 0;
		}
		return std::atoi(str);
	}

	int WIN_ENTRY _amsg_exit(int reason) {
		DEBUG_LOG("_amsg_exit(%d)\n", reason);
		abort_and_log("_amsg_exit");
		return reason;
	}

	void WIN_ENTRY _invoke_watson(const uint16_t *, const uint16_t *, const uint16_t *, unsigned int, uintptr_t) {
		DEBUG_LOG("_invoke_watson\n");
		abort_and_log("_invoke_watson");
	}

	void WIN_ENTRY terminateShim() {
		abort_and_log("terminate");
	}

	int WIN_ENTRY _except_handler4_common(void *, void *, void *, void *) {
		DEBUG_LOG("_except_handler4_common\n");
		return 0;
	}

	long WIN_ENTRY _XcptFilter(unsigned long code, void *) {
		DEBUG_LOG("_XcptFilter(%lu)\n", code);
		return 0;
	}

	int WIN_ENTRY _get_wpgmptr(uint16_t** pValue){
		DEBUG_LOG("_get_wpgmptr(%p)\n", pValue);
		if(!pValue) return 22;

		char exe_path[PATH_MAX];
		ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
		if(len == -1){
			return 2;
		}
		exe_path[len] = 0;

		std::vector<uint16_t> wStr = stringToWideString(exe_path);
		_wpgmptr = new uint16_t[wStr.size() + 1];
		std::copy(wStr.begin(), wStr.end(), _wpgmptr);
		_wpgmptr[wStr.size()] = 0;

		*pValue = _wpgmptr;
		return 0;
	}

	int WIN_ENTRY _wsplitpath_s(const uint16_t * path, uint16_t * drive, size_t driveNumberOfElements, uint16_t *dir, size_t dirNumberOfElements,
		uint16_t * fname, size_t nameNumberOfElements, uint16_t * ext, size_t extNumberOfElements){
		DEBUG_LOG("_wsplitpath_s - ");
		if(!path){
			DEBUG_LOG("no path\n");
			return 22;
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
			if (dir_len >= dirNumberOfElements) return 34;
			wstrncpy(dir, path, dir_len);
			dir[dir_len] = L'\0';
		}

		if (fname && nameNumberOfElements) {
			size_t fname_len = dot ? (size_t)(dot - filename_start) : wstrlen(filename_start);
			if (fname_len >= nameNumberOfElements) return 34;
			wstrncpy(fname, filename_start, fname_len);
			fname[fname_len] = L'\0';
		}

		if (ext && extNumberOfElements && dot) {
			size_t ext_len = wstrlen(dot);
			if (ext_len >= extNumberOfElements) return 34;
			wstrncpy(ext, dot, ext_len);
			ext[ext_len] = L'\0';
		}

		if (drive && driveNumberOfElements && path[1] == L':' && path[2] == L'/') {
			if (driveNumberOfElements < 3) return 34;
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

		auto *dup = static_cast<uint16_t *>(malloc((strLen + 1) * sizeof(uint16_t)));
		if(!dup) return nullptr;

		for(size_t i = 0; i <= strLen; i++){
			dup[i] = strSource[i];
		}

		// std::string dst_str = wideStringToString(dup);
		// DEBUG_LOG(" --> %s\n", dst_str.c_str());
		return dup;
	}

	int WIN_ENTRY _waccess_s(const uint16_t* path, int mode){
		std::string original = wideStringToString(path);
		DEBUG_LOG("_waccess_s %s\n", original.c_str());
		std::filesystem::path host = files::pathFromWindows(original.c_str());
		std::string candidate;
		if (!host.empty()) {
			candidate = host.string();
		} else {
			candidate = original;
			std::replace(candidate.begin(), candidate.end(), '\\', '/');
		}
		return access(candidate.c_str(), mode);
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

	int WIN_ENTRY _vswprintf_c_l(uint16_t* buffer, size_t size, const uint16_t* format, ...) {
		DEBUG_LOG("_vswprintf_c_l\n");
		if (!buffer || !format || size == 0)
			return -1;

		std::string narrow_fmt = wideStringToString(format);
		DEBUG_LOG("\tFmt: %s\n", narrow_fmt.c_str());
		
		va_list args;
		va_start(args, format);
		int required = vsnprintf(nullptr, 0, narrow_fmt.c_str(), args);
		va_end(args);
		if (required < 0) {
			buffer[0] = 0;
			return -1;
		}

		char buffer_narrow[required + 1];
		va_start(args, format);
		vsnprintf(buffer_narrow, required + 1, narrow_fmt.c_str(), args);
		va_end(args);
		DEBUG_LOG("\tBuffer: %s\n", buffer_narrow);

		std::vector<uint16_t> wide = stringToWideString(buffer_narrow);
		size_t copy_len = std::min(wide.size(), size - 1);
		std::memcpy(buffer, wide.data(), copy_len * sizeof(uint16_t));
		buffer[copy_len] = 0;

		return static_cast<int>(copy_len);
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

	FILE* WIN_ENTRY _wfsopen(const uint16_t* filename, const uint16_t* mode, int shflag){
		if (!filename || !mode) return nullptr;
		std::string fname_str = wideStringToString(filename);
		std::string mode_str = wideStringToString(mode);
		DEBUG_LOG("_wfsopen file %s, mode %s\n", fname_str.c_str(), mode_str.c_str());

		(void)shflag;
		return fopen(fname_str.c_str(), mode_str.c_str());
	}

	int WIN_ENTRY puts(const char *str) {
		if (!str) {
			str = "(null)";
		}
		DEBUG_LOG("puts %s\n", str);
		if (std::fputs(str, stdout) < 0)
			return EOF;
		if (std::fputc('\n', stdout) == EOF)
			return EOF;
		return 0;
	}

	int WIN_ENTRY fclose(FILE* stream){
		return ::fclose(stream);
	}

	int WIN_ENTRY _flushall(){
		DEBUG_LOG("flushall\n");
		int count = 0;

		if (msvcrt::fflush(stdin) == 0) count++;
		if (msvcrt::fflush(stdout) == 0) count++;
		if (msvcrt::fflush(stderr) == 0) count++;

		return count;
	}

	int* WIN_ENTRY _errno() {
		return &errno;
	}

	intptr_t WIN_ENTRY _wspawnvp(int mode, const uint16_t* cmdname, const uint16_t* const * argv) {
		if (!cmdname || !argv) {
			errno = EINVAL;
			return -1;
		}

		std::string command = wideStringToString(cmdname);
		DEBUG_LOG("_wspawnvp(mode=%d, cmd=%s)\n", mode, command.c_str());

		std::vector<std::string> argStorage;
		for (const uint16_t *const *cursor = argv; *cursor; ++cursor) {
			argStorage.emplace_back(wideStringToString(*cursor));
		}
		if (argStorage.empty()) {
			argStorage.emplace_back(command);
		}

		auto resolved = processes::resolveExecutable(command, true);
		if (!resolved) {
			errno = ENOENT;
			DEBUG_LOG("\tfailed to resolve executable for %s\n", command.c_str());
			return -1;
		}

		pid_t pid = -1;
		int spawnResult = processes::spawnViaWibo(*resolved, argStorage, &pid);
		if (spawnResult != 0) {
			errno = spawnResult;
			DEBUG_LOG("\tspawnViaWibo failed: %d\n", spawnResult);
			return -1;
		}

		constexpr int P_WAIT = 0;
		constexpr int P_DETACH = 2;

		if (mode == P_WAIT) {
			int status = 0;
			if (waitpid(pid, &status, 0) == -1) {
				DEBUG_LOG("\twaitpid failed: %d\n", errno);
				return -1;
			}
			if (WIFEXITED(status)) {
				return static_cast<intptr_t>(WEXITSTATUS(status));
			}
			if (WIFSIGNALED(status)) {
				errno = EINTR;
			}
			return -1;
		}

		if (mode == P_DETACH) {
			return 0;
		}

		// _P_NOWAIT and unknown flags: return process id
		return static_cast<intptr_t>(pid);
	}

	int WIN_ENTRY _wunlink(const uint16_t *filename){
		std::string str = wideStringToString(filename);
		DEBUG_LOG("_wunlink %s\n", str.c_str());
		return unlink(str.c_str());
	}

	uint16_t* WIN_ENTRY _wfullpath(uint16_t* absPath, const uint16_t* relPath, size_t maxLength){
		std::string relPathStr = wideStringToString(relPath);
		DEBUG_LOG("_wfullpath, relpath %s\n", relPathStr.c_str());
		if(!relPath) return nullptr;

		char resolved[PATH_MAX];
		char* realpathResult = realpath(relPathStr.c_str(), resolved);
		std::string finalPath;

		if(realpathResult){
			finalPath = resolved;
		}
		else if (!relPathStr.empty() && relPathStr[0] == '\\') {
			// this is an absolute path - normalize it before assigning finalPath
    		for (char& c : relPathStr) if (c == '\\') c = '/';
			finalPath = relPathStr;
		}
		else {
			DEBUG_LOG("\tcould not find realpath, trying cwd...\n");
			char cwd[PATH_MAX];
			if(!getcwd(cwd, sizeof(cwd))){
				return nullptr;
			}
			finalPath = std::string(cwd) + "/" + relPathStr;
		}

		std::vector<uint16_t> wResolved = stringToWideString(finalPath.c_str());
	    // If caller provided a buffer, check size
	    if (absPath) {
	        if (wResolved.size() + 1 > maxLength) {
	            return nullptr; // too small
	        }
	        std::copy(wResolved.begin(), wResolved.end(), absPath);
	        absPath[wResolved.size()] = 0;

			std::string absPathStr = wideStringToString(absPath);
			DEBUG_LOG("\t-> abspath %s\n", absPathStr.c_str());
	        return absPath;
	    } else {
	        // Windows behavior: if absPath == NULL, allocate new
	        auto *newBuf = new uint16_t[wResolved.size() + 1];
	        std::copy(wResolved.begin(), wResolved.end(), newBuf);
	        newBuf[wResolved.size()] = 0;

			std::string absPathStr = wideStringToString(newBuf);
			DEBUG_LOG("\t-> abspath %s\n", absPathStr.c_str());
	        return newBuf;
	    }

	}
}


static void *resolveByName(const char *name) {
	if (strcmp(name, "__set_app_type") == 0) return (void *) msvcrt::__set_app_type;
	if (strcmp(name, "_fmode") == 0) return (void *)&msvcrt::_fmode;
    if (strcmp(name, "_commode") == 0) return (void *)&msvcrt::_commode;
	if (strcmp(name, "__initenv") == 0) return (void *)&msvcrt::__initenv;
	if (strcmp(name, "__winitenv") == 0) return (void *)&msvcrt::__winitenv;
	if (strcmp(name, "__p__fmode") == 0) return (void *) msvcrt::__p__fmode;
	if (strcmp(name, "__p__commode") == 0) return (void *) msvcrt::__p__commode;
	if (strcmp(name, "_initterm") == 0) return (void *)msvcrt::_initterm;
	if (strcmp(name, "_initterm_e") == 0) return (void *)msvcrt::_initterm_e;
	if (strcmp(name, "_controlfp_s") == 0) return (void *)msvcrt::_controlfp_s;
	if (strcmp(name, "_onexit") == 0) return (void*)msvcrt::_onexit;
	if (strcmp(name, "__getmainargs") == 0) return (void*)msvcrt::__getmainargs;
	if (strcmp(name, "__wgetmainargs") == 0) return (void*)msvcrt::__wgetmainargs;
	if (strcmp(name, "setlocale") == 0) return (void*)msvcrt::setlocale;
	if (strcmp(name, "__mb_cur_max") == 0) return (void *)&msvcrt::mbCurMaxValue;
	if (strcmp(name, "__setusermatherr") == 0) return (void *)msvcrt::__setusermatherr;
	if (strcmp(name, "_wdupenv_s") == 0) return (void*)msvcrt::_wdupenv_s;
	if (strcmp(name, "strlen") == 0) return (void *)msvcrt::strlen;
	if (strcmp(name, "strcmp") == 0) return (void *)msvcrt::strcmp;
	if (strcmp(name, "strncmp") == 0) return (void *)msvcrt::strncmp;
	if (strcmp(name, "malloc") == 0) return (void*)msvcrt::malloc;
	if (strcmp(name, "calloc") == 0) return (void*)msvcrt::calloc;
	if (strcmp(name, "_malloc_crt") == 0) return (void*)msvcrt::_malloc_crt;
	if (strcmp(name, "_lock") == 0) return (void*)msvcrt::_lock;
	if (strcmp(name, "_unlock") == 0) return (void*)msvcrt::_unlock;
	if (strcmp(name, "__dllonexit") == 0) return (void*)msvcrt::__dllonexit;
	if (strcmp(name, "free") == 0) return (void*)msvcrt::free;
	if (strcmp(name, "_wcsicmp") == 0) return (void*)msvcrt::_wcsicmp;
	if (strcmp(name, "_wmakepath_s") == 0) return (void*)msvcrt::_wmakepath_s;
	if (strcmp(name, "_wputenv_s") == 0) return (void*)msvcrt::_wputenv_s;
	if (strcmp(name, "_get_wpgmptr") == 0) return (void*)msvcrt::_get_wpgmptr;
	if (strcmp(name, "_wsplitpath_s") == 0) return (void*)msvcrt::_wsplitpath_s;
	if (strcmp(name, "wcscat_s") == 0) return (void*)msvcrt::wcscat_s;
	if (strcmp(name, "_wcsdup") == 0) return (void*)msvcrt::_wcsdup;
	if (strcmp(name, "memset") == 0) return (void*)msvcrt::memset;
	if (strcmp(name, "memcpy") == 0) return (void*)msvcrt::memcpy;
	if (strcmp(name, "memmove") == 0) return (void*)msvcrt::memmove;
	if (strcmp(name, "memcmp") == 0) return (void*)msvcrt::memcmp;
	if (strcmp(name, "fflush") == 0) return (void*)msvcrt::fflush;
	if (strcmp(name, "fopen") == 0) return (void*)msvcrt::fopen;
	if (strcmp(name, "fseek") == 0) return (void*)msvcrt::fseek;
	if (strcmp(name, "ftell") == 0) return (void*)msvcrt::ftell;
	if (strcmp(name, "feof") == 0) return (void*)msvcrt::feof;
	if (strcmp(name, "fgetws") == 0) return (void*)msvcrt::fgetws;
	if (strcmp(name, "fgetwc") == 0) return (void*)msvcrt::fgetwc;
	if (strcmp(name, "fputws") == 0) return (void*)msvcrt::fputws;
	if (strcmp(name, "_wfopen_s") == 0) return (void*)msvcrt::_wfopen_s;
	if (strcmp(name, "wcsspn") == 0) return (void*)msvcrt::wcsspn;
	if (strcmp(name, "_wtol") == 0) return (void*)msvcrt::_wtol;
	if (strcmp(name, "_wcsupr_s") == 0) return (void*)msvcrt::_wcsupr_s;
	if (strcmp(name, "_wcslwr_s") == 0) return (void*)msvcrt::_wcslwr_s;
	if (strcmp(name, "_dup2") == 0) return (void*)msvcrt::_dup2;
	if (strcmp(name, "_isatty") == 0) return (void*)msvcrt::_isatty;
	if (strcmp(name, "towlower") == 0) return (void*)msvcrt::towlower;
	if (strcmp(name, "_ftime64_s") == 0) return (void*)msvcrt::_ftime64_s;
	if (strcmp(name, "_crt_debugger_hook") == 0) return (void*)msvcrt::_crt_debugger_hook;
	if (strcmp(name, "_configthreadlocale") == 0) return (void*)msvcrt::_configthreadlocale;
	if (strcmp(name, "_amsg_exit") == 0) return (void*)msvcrt::_amsg_exit;
	if (strcmp(name, "_invoke_watson") == 0) return (void*)msvcrt::_invoke_watson;
	if (strcmp(name, "_except_handler4_common") == 0) return (void*)msvcrt::_except_handler4_common;
	if (strcmp(name, "_XcptFilter") == 0) return (void*)msvcrt::_XcptFilter;
	if (strcmp(name, "?terminate@@YAXXZ") == 0) return (void*)msvcrt::terminateShim;
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
	if (strcmp(name, "puts") == 0) return (void*)msvcrt::puts;
	if (strcmp(name, "fclose") == 0) return (void*)msvcrt::fclose;
	if (strcmp(name, "_flushall") == 0) return (void*)msvcrt::_flushall;
	if (strcmp(name, "_errno") == 0) return (void*)msvcrt::_errno;
	if (strcmp(name, "_wspawnvp") == 0) return (void*)msvcrt::_wspawnvp;
	if (strcmp(name, "_wunlink") == 0) return (void*)msvcrt::_wunlink;
	if (strcmp(name, "_wfullpath") == 0) return (void*)msvcrt::_wfullpath;
	if (strcmp(name, "_cexit") == 0) return (void*)msvcrt::_cexit;
	if (strcmp(name, "_iob") == 0) return (void*)msvcrt::standardIobEntries();
	if (strcmp(name, "abort") == 0) return (void*)msvcrt::abort;
	if (strcmp(name, "atoi") == 0) return (void*)msvcrt::atoi;
	if (strcmp(name, "fprintf") == 0) return (void*)msvcrt::fprintf;
	if (strcmp(name, "vfprintf") == 0) return (void*)msvcrt::vfprintf;
	if (strcmp(name, "fputc") == 0) return (void*)msvcrt::fputc;
	if (strcmp(name, "fwrite") == 0) return (void*)msvcrt::fwrite;
	if (strcmp(name, "localeconv") == 0) return (void*)msvcrt::localeconv;
	if (strcmp(name, "signal") == 0) return (void*)msvcrt::signal;
	if (strcmp(name, "strchr") == 0) return (void*)msvcrt::strchr;
	if (strcmp(name, "strerror") == 0) return (void*)msvcrt::strerror;
	if (strcmp(name, "wcslen") == 0) return (void*)msvcrt::wcslen;
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
