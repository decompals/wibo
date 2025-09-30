#include "common.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <clocale>
#include <cmath>
#include <cctype>
#include <float.h>
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
#include <ctime>
#include <string>
#include <strings.h>
#include <type_traits>
#include <unordered_map>
#include <unistd.h>
#include <vector>
#include <spawn.h>
#include <sys/wait.h>
#include <math.h>
#include <utime.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#ifndef O_BINARY
#define O_BINARY 0
#endif
#include "files.h"
#include "processes.h"
#include "strutil.h"

typedef void (*_PVFV)();
typedef int (*_PIFV)();
using _onexit_t = _PIFV;

extern "C" char **environ;

struct _utimbuf {
	long actime;
	long modtime;
};

struct _timeb {
	time_t time;
	unsigned short millitm;
	short timezone;
	short dstflag;
};

namespace msvcrt {
	int _commode;
	int _fmode;
	char** __initenv;
	uint16_t** __winitenv;
	uint16_t* _wpgmptr = nullptr;
	char* _pgmptr = nullptr;
	constexpr int MB_CP_ANSI = -3;
	constexpr int MB_CP_OEM = -2;
	constexpr int MB_CP_LOCALE = -4;
	constexpr int MB_CP_SBCS = 0;
	constexpr int MB_CP_UTF8 = -5;

	static unsigned int mbCurMaxValue = 1;
	static int mbCodePageSetting = MB_CP_ANSI;
	static unsigned int floatingPointControlWord = 0x0009001F; // _CW_DEFAULT for x87

	constexpr unsigned short PCTYPE_UPPER = 0x0001;
	constexpr unsigned short PCTYPE_LOWER = 0x0002;
	constexpr unsigned short PCTYPE_DIGIT = 0x0004;
	constexpr unsigned short PCTYPE_SPACE = 0x0008;
	constexpr unsigned short PCTYPE_PUNCT = 0x0010;
	constexpr unsigned short PCTYPE_CONTROL = 0x0020;
	constexpr unsigned short PCTYPE_BLANK = 0x0040;
	constexpr unsigned short PCTYPE_HEX = 0x0080;
	constexpr unsigned short PCTYPE_LEADBYTE = 0x8000;

	constexpr unsigned char _MS = 0x01;
	constexpr unsigned char _MP = 0x02;
	constexpr unsigned char _M1 = 0x04;
	constexpr unsigned char _M2 = 0x08;
	constexpr unsigned char _SBUP = 0x10;
	constexpr unsigned char _SBLOW = 0x20;

	using ByteRange = std::pair<uint8_t, uint8_t>;

	std::array<unsigned char, 257> &mbctypeTable() {
		static std::array<unsigned char, 257> table = {};
		return table;
	}

	template <size_t N>
	void setMbctypeFlag(unsigned char flag, const std::array<ByteRange, N> &ranges) {
		auto &table = mbctypeTable();
		for (const auto &range : ranges) {
			for (int value = range.first; value <= range.second; ++value) {
				table[static_cast<size_t>(value)] |= flag;
			}
		}
	}

	unsigned int mbCurMaxForCodePage(int codepage);

	void updateMbctypeForCodePage(int codepage) {
		auto &table = mbctypeTable();
		table.fill(0);

		switch (codepage) {
		case 932: {
			const std::array<ByteRange, 2> lead{{ByteRange{0x81, 0x9F}, ByteRange{0xE0, 0xFC}}};
			const std::array<ByteRange, 2> trail{{ByteRange{0x40, 0x7E}, ByteRange{0x80, 0xFC}}};
			setMbctypeFlag(_M1, lead);
			setMbctypeFlag(_M2, trail);
			break;
		}
		case 936: {
			const std::array<ByteRange, 1> lead{{ByteRange{0x81, 0xFE}}};
			const std::array<ByteRange, 1> trail{{ByteRange{0x40, 0xFE}}};
			setMbctypeFlag(_M1, lead);
			setMbctypeFlag(_M2, trail);
			break;
		}
		case 949: {
			const std::array<ByteRange, 1> lead{{ByteRange{0x81, 0xFE}}};
			const std::array<ByteRange, 3> trail{{ByteRange{0x41, 0x5A}, ByteRange{0x61, 0x7A}, ByteRange{0x81, 0xFE}}};
			setMbctypeFlag(_M1, lead);
			setMbctypeFlag(_M2, trail);
			break;
		}
		case 950: {
			const std::array<ByteRange, 1> lead{{ByteRange{0x81, 0xFE}}};
			const std::array<ByteRange, 2> trail{{ByteRange{0x40, 0x7E}, ByteRange{0xA1, 0xFE}}};
			setMbctypeFlag(_M1, lead);
			setMbctypeFlag(_M2, trail);
			break;
		}
		case 1361: {
			const std::array<ByteRange, 1> lead{{ByteRange{0x81, 0xFE}}};
			const std::array<ByteRange, 2> trail{{ByteRange{0x31, 0x7E}, ByteRange{0x81, 0xFE}}};
			setMbctypeFlag(_M1, lead);
			setMbctypeFlag(_M2, trail);
			break;
		}
		default:
			break;
		}
	}

	std::once_flag &mbctypeInitFlag() {
		static std::once_flag flag;
		return flag;
	}

	void ensureMbctypeInitialized() {
		std::call_once(mbctypeInitFlag(), []() {
			updateMbctypeForCodePage(mbCodePageSetting);
			mbCurMaxValue = mbCurMaxForCodePage(mbCodePageSetting);
		});
	}

	bool isLeadByte(unsigned char byte) {
		ensureMbctypeInitialized();
		return (mbctypeTable()[byte] & _M1) != 0;
	}

	bool isTrailByte(unsigned char byte) {
		ensureMbctypeInitialized();
		return (mbctypeTable()[byte] & _M2) != 0;
	}

	std::once_flag &pctypeInitFlag() {
		static std::once_flag flag;
		return flag;
	}

	std::array<unsigned short, 257> &pctypeTable() {
		static std::array<unsigned short, 257> table = {};
		std::call_once(pctypeInitFlag(), []() {
			table[0] = 0;
			for (int i = 0; i < 256; ++i) {
				unsigned short flags = 0;
				unsigned char ch = static_cast<unsigned char>(i);
				if (std::isupper(ch)) flags |= PCTYPE_UPPER;
				if (std::islower(ch)) flags |= PCTYPE_LOWER;
				if (std::isdigit(ch)) flags |= PCTYPE_DIGIT;
				if (std::isspace(ch)) flags |= PCTYPE_SPACE;
				if (std::iscntrl(ch)) flags |= PCTYPE_CONTROL;
				if (ch == ' ' || ch == '\t') flags |= PCTYPE_BLANK;
				if (std::ispunct(ch)) flags |= PCTYPE_PUNCT;
				if (std::isxdigit(ch)) flags |= PCTYPE_HEX;
				if (isLeadByte(ch)) flags |= PCTYPE_LEADBYTE;
				table[i + 1] = flags;
			}
		});
		return table;
	}

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

	int WIN_ENTRY _except_handler4_common(void *, void *, void *, void *);
	std::vector<std::string> &putenvStorage() {
		static std::vector<std::string> storage;
		return storage;
	}

	IOBProxy *standardIobEntries() {
		static IOBProxy entries[3] = {};
		return entries;
	}

	IOBProxy *WIN_ENTRY __iob_func() {
		return standardIobEntries();
	}

	IOBProxy *WIN_ENTRY __p__iob() {
		return standardIobEntries();
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

	void WIN_ENTRY setbuf(FILE *stream, char *buffer) {
		DEBUG_LOG("setbuf(%p, %p)\n", stream, buffer);
		if (!stream) {
			return;
		}
		FILE *host = mapToHostFile(stream);
		if (buffer) {
			setvbuf(host, buffer, _IOFBF, BUFSIZ);
		} else {
			setvbuf(host, nullptr, _IONBF, 0);
		}
	}

	void WIN_ENTRY _splitpath(const char *path, char *drive, char *dir, char *fname, char *ext) {
		if (drive) drive[0] = '\0';
		if (dir) dir[0] = '\0';
		if (fname) fname[0] = '\0';
		if (ext) ext[0] = '\0';

		if (!path) {
			errno = EINVAL;
			return;
		}

		const char *cursor = path;
		if (cursor[0] && cursor[1] == ':') {
			if (drive) {
				drive[0] = cursor[0];
				drive[1] = ':';
				drive[2] = '\0';
			}
			cursor += 2;
		}

		const char *dirEnd = nullptr;
		for (const char *scan = cursor; *scan; ++scan) {
			if (*scan == '/' || *scan == '\\') {
				dirEnd = scan + 1;
			}
		}

		const char *filename = cursor;
		if (dirEnd) {
			if (dir) {
				size_t dirLen = static_cast<size_t>(dirEnd - cursor);
				std::memcpy(dir, cursor, dirLen);
				dir[dirLen] = '\0';
			}
			filename = dirEnd;
		}

		const char *extStart = nullptr;
		for (const char *scan = filename; *scan; ++scan) {
			if (*scan == '.') {
				extStart = scan;
			}
		}

		const char *nameEnd = extStart ? extStart : filename + std::strlen(filename);

		if (fname) {
			auto nameLen = static_cast<size_t>(nameEnd - filename);
			std::memcpy(fname, filename, nameLen);
			fname[nameLen] = '\0';
		}
		if (ext && extStart) {
			std::strcpy(ext, extStart);
		}

		DEBUG_LOG("_splitpath(%s) -> drive='%s' dir='%s' fname='%s' ext='%s'\n",
				  path,
				  drive ? drive : "",
				  dir ? dir : "",
				  fname ? fname : "",
				  ext ? ext : "");
	}

	int WIN_ENTRY _fileno(FILE *stream) {
		DEBUG_LOG("_fileno(%p)\n", stream);
		if (!stream) {
			errno = EINVAL;
			return -1;
		}
		FILE *host = mapToHostFile(stream);
		return ::fileno(host);
	}

	unsigned int mbCurMaxForCodePage(int codepage) {
		switch (codepage) {
		case MB_CP_SBCS:
		case MB_CP_ANSI:
		case MB_CP_OEM:
		case MB_CP_LOCALE:
			return 1;
		case MB_CP_UTF8:
		case 65001:
			return 4;
		case 932:
		case 936:
		case 949:
		case 950:
		case 1361:
			return 2;
		default:
			return 1;
		}
	}

	void refreshMbCurMax() {
		ensureMbctypeInitialized();
		mbCurMaxValue = mbCurMaxForCodePage(mbCodePageSetting);
	}

	int WIN_ENTRY _getmbcp() {
		ensureMbctypeInitialized();
		DEBUG_LOG("_getmbcp() -> %d\n", mbCodePageSetting);
		return mbCodePageSetting;
	}

	unsigned int* WIN_ENTRY __p___mb_cur_max() {
		ensureMbctypeInitialized();
		DEBUG_LOG("__p___mb_cur_max() -> %u\n", mbCurMaxValue);
		return &mbCurMaxValue;
	}

	int WIN_ENTRY _setmbcp(int codepage) {
		DEBUG_LOG("_setmbcp(%d)\n", codepage);
		ensureMbctypeInitialized();

		switch (codepage) {
		case MB_CP_SBCS:
		case MB_CP_UTF8:
		case MB_CP_OEM:
		case MB_CP_ANSI:
		case MB_CP_LOCALE:
			break;
		default:
			if (codepage < 0) {
				errno = EINVAL;
				return -1;
			}
			break;
		}

		mbCodePageSetting = codepage;
		updateMbctypeForCodePage(codepage);
		mbCurMaxValue = mbCurMaxForCodePage(codepage);
		return 0;
	}

	unsigned char *WIN_ENTRY __p__mbctype() {
		ensureMbctypeInitialized();
		DEBUG_LOG("__p__mbctype() -> %p\n", mbctypeTable().data());
		return mbctypeTable().data();
	}

	unsigned short **WIN_ENTRY __p__pctype() {
		DEBUG_LOG("__p__pctype()\n");
		static unsigned short *pointer = nullptr;
		pointer = pctypeTable().data() + 1;
		return &pointer;
	}

	int WIN_ENTRY _isctype(int ch, int mask) {
		DEBUG_LOG("_isctype(%d, %d)\n", ch, mask);
		if (ch == EOF) {
			return 0;
		}
		if (ch < 0 || ch > 255) {
			return 0;
		}
		return (pctypeTable()[static_cast<size_t>(ch) + 1] & mask) != 0;
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
				if (!wibo::guestExecutablePath.empty()) {
					auto exePath = wibo::guestExecutablePath.parent_path();
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
		DEBUG_LOG("STUB: __set_app_type(%d)\n", at);
		(void)at;
	}

	int* WIN_FUNC __p__fmode() {
		DEBUG_LOG("__p__fmode() -> %p\n", &_fmode);
		return &_fmode;
	}

	int* WIN_FUNC __p__commode() {
		DEBUG_LOG("__p__commode() -> %p\n", &_commode);
		return &_commode;
	}

	void WIN_ENTRY _initterm(const _PVFV *ppfn, const _PVFV* end) {
		DEBUG_LOG("_initterm(%p, %p)\n", ppfn, end);
		for (; ppfn < end; ppfn++) {
			_PVFV func = *ppfn;
			if (func) {
				DEBUG_LOG("_initterm: calling %p\n", func);
				func();
			}
		}
	}

	int WIN_ENTRY _initterm_e(const _PIFV *ppfn, const _PIFV *end) {
		DEBUG_LOG("_initterm_e(%p, %p)\n", ppfn, end);
		for (; ppfn < end; ppfn++) {
			_PIFV func = *ppfn;
			if (func) {
				int err = func();
				DEBUG_LOG("_initterm_e: calling %p -> %d\n", func, err);
				if (err != 0)
					return err;
			}
		}
		return 0;
	}

	unsigned int WIN_ENTRY _controlfp(unsigned int newControl, unsigned int mask) {
		DEBUG_LOG("_controlfp(newControl=%08x, mask=%08x)\n", newControl, mask);
		unsigned int previous = floatingPointControlWord;
		if (mask != 0) {
			floatingPointControlWord = (floatingPointControlWord & ~mask) | (newControl & mask);
		}
		return previous;
	}

	int WIN_ENTRY _controlfp_s(unsigned int *currentControl, unsigned int newControl, unsigned int mask) {
		DEBUG_LOG("_controlfp_s(currentControl=%p, newControl=%08x, mask=%08x)\n", currentControl, newControl, mask);
		if (mask != 0 && (mask & 0xFF000000) != 0) {
			// Unsupported bits: match real CRT behaviour by ignoring but logging.
			DEBUG_LOG("STUB: _controlfp_s unsupported mask bits %08x\n", mask);
		}
		if (mask != 0) {
			floatingPointControlWord = (floatingPointControlWord & ~mask) | (newControl & mask);
		}
		if (currentControl) {
			*currentControl = floatingPointControlWord;
		}
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
		DEBUG_LOG("getenv(%s)\n", varname);
		return std::getenv(varname);
	}

	char*** WIN_ENTRY __p___initenv() {
		DEBUG_LOG("__p___initenv() -> %p\n", &__initenv);
		return &__initenv;
	}

	char* WIN_ENTRY strcat(char *dest, const char *src) {
		VERBOSE_LOG("strcat(%s, %s)\n", dest, src);
		return std::strcat(dest, src);
	}

	char* WIN_ENTRY strcpy(char *dest, const char *src) {
		VERBOSE_LOG("strcpy(%s, %s)\n", dest, src);
		return std::strcpy(dest, src);
	}

	int WIN_ENTRY _access(const char *path, int mode) {
		DEBUG_LOG("_access(%s, %d)\n", path ? path : "(null)", mode);
		if (!path) {
			errno = EINVAL;
			return -1;
		}

		auto hostPath = files::pathFromWindows(path);
		int flags = F_OK;
		if (mode & 2) {
			flags |= W_OK;
		}
		if (mode & 4) {
			flags |= R_OK;
		}
		if (mode & 1) {
			flags |= X_OK;
		}

		if (::access(hostPath.c_str(), flags) == 0) {
			return 0;
		}

		return -1;
	}

	int WIN_ENTRY _ismbblead(unsigned int c) {
		DEBUG_LOG("_ismbblead(%d)\n", c);
		if (c > 0xFF) {
			return 0;
		}
		return isLeadByte(static_cast<unsigned char>(c)) ? 1 : 0;
	}

	int WIN_ENTRY _ismbbtrail(unsigned int c) {
		DEBUG_LOG("_ismbbtrail(%d)\n", c);
		if (c > 0xFF) {
			return 0;
		}
		return isTrailByte(static_cast<unsigned char>(c)) ? 1 : 0;
	}

	int WIN_ENTRY _ismbcspace(unsigned int c) {
		DEBUG_LOG("_ismbcspace(%d)\n", c);
		if (c <= 0xFF) {
			return std::isspace(static_cast<unsigned char>(c)) ? 1 : 0;
		}

		unsigned char lead = static_cast<unsigned char>((c >> 8) & 0xFF);
		unsigned char trail = static_cast<unsigned char>(c & 0xFF);
		if (isLeadByte(lead) && isTrailByte(trail)) {
			// Treat known double-byte ideographic space as whitespace (CP932/936 etc.)
			if ((lead == 0x81 && trail == 0x40) || (lead == 0xA1 && trail == 0xA1)) {
				return 1;
			}
		}
		return 0;
	}

	void WIN_ENTRY _mbccpy(unsigned char *dest, const unsigned char *src) {
		DEBUG_LOG("_mbccpy(%s, %s)\n", dest, src);
		if (!dest || !src) {
			return;
		}

		dest[0] = src[0];
		if (isLeadByte(src[0]) && src[1]) {
			dest[1] = src[1];
		}
	}

	unsigned char* WIN_ENTRY _mbsinc(const unsigned char *str) {
		DEBUG_LOG("_mbsinc(%s)\n", str);
		if (!str) {
			return nullptr;
		}
		if (*str == '\0') {
			return const_cast<unsigned char *>(str);
		}
		if (isLeadByte(static_cast<unsigned char>(*str)) && str[1] != '\0') {
			return const_cast<unsigned char *>(str + 2);
		}
		return const_cast<unsigned char *>(str + 1);
	}

	unsigned char* WIN_ENTRY _mbsdec(const unsigned char *start, const unsigned char *current) {
		DEBUG_LOG("_mbsdec(%s, %s)\n", start, current);
		if (!start || !current || current <= start) {
			DEBUG_LOG("_mbsdec invalid args start=%p current=%p\n", start, current);
			return nullptr;
		}

		const unsigned char *iter = start;
		const unsigned char *prev = nullptr;
		while (iter < current) {
			if (*iter == '\0') {
				break;
			}
			prev = iter;
			const unsigned char *next = _mbsinc(iter);
			if (next >= current) {
				break;
			}
			iter = next;
		}

		if (!prev) {
			long diff = static_cast<long>(current - start);
			DEBUG_LOG("_mbsdec fallback start=%p current=%p diff=%ld first-bytes=%02x %02x %02x %02x\n",
				start, current, diff,
				start ? start[0] : 0, start ? start[1] : 0,
				start ? start[2] : 0, start ? start[3] : 0);
			const unsigned char *fallback = current ? current - 1 : current;
			if (diff >= 2 && start && start[0] == 0 && start[1] != 0) {
				fallback = current - 2;
			}
			return const_cast<unsigned char *>(fallback);
		}
		return const_cast<unsigned char *>(prev);
	}

	unsigned int WIN_ENTRY _mbclen(const unsigned char *str) {
		DEBUG_LOG("_mbclen(%s)\n", str);
		if (!str || *str == '\0') {
			return 0;
		}
		return (isLeadByte(*str) && str[1] != '\0') ? 2U : 1U;
	}

	int WIN_ENTRY _mbscmp(const unsigned char *lhs, const unsigned char *rhs) {
		DEBUG_LOG("_mbscmp(%s, %s)\n", lhs, rhs);
		if (!lhs || !rhs) {
			return (lhs == rhs) ? 0 : (lhs ? 1 : -1);
		}
		return std::strcmp(reinterpret_cast<const char *>(lhs), reinterpret_cast<const char *>(rhs));
	}

	int WIN_ENTRY _mbsicmp(const unsigned char *lhs, const unsigned char *rhs) {
		DEBUG_LOG("_mbsicmp(%s, %s)\n", lhs, rhs);
		if (!lhs || !rhs) {
			return (lhs == rhs) ? 0 : (lhs ? 1 : -1);
		}
		return strcasecmp(reinterpret_cast<const char *>(lhs), reinterpret_cast<const char *>(rhs));
	}

	unsigned char* WIN_ENTRY _mbsstr(const unsigned char *haystack, const unsigned char *needle) {
		DEBUG_LOG("_mbsstr(%s, %s)\n", haystack, needle);
		if (!haystack || !needle) {
			return nullptr;
		}
		const char *result = std::strstr(reinterpret_cast<const char *>(haystack), reinterpret_cast<const char *>(needle));
		return result ? reinterpret_cast<unsigned char *>(const_cast<char *>(result)) : nullptr;
	}

	unsigned char* WIN_ENTRY _mbschr(const unsigned char *str, unsigned int ch) {
		DEBUG_LOG("_mbschr(%s, %d)\n", str, ch);
		if (!str) {
			return nullptr;
		}
		unsigned char target = static_cast<unsigned char>(ch & 0xFF);
		const char *result = std::strchr(reinterpret_cast<const char *>(str), target);
		return result ? reinterpret_cast<unsigned char *>(const_cast<char *>(result)) : nullptr;
	}

	unsigned char* WIN_ENTRY _mbsrchr(const unsigned char *str, unsigned int ch) {
		DEBUG_LOG("_mbsrchr(%s, %d)\n", str, ch);
		if (!str) {
			return nullptr;
		}
		unsigned char target = static_cast<unsigned char>(ch & 0xFF);
		const char *result = std::strrchr(reinterpret_cast<const char *>(str), target);
		return result ? reinterpret_cast<unsigned char *>(const_cast<char *>(result)) : nullptr;
	}

	unsigned char* WIN_ENTRY _mbslwr(unsigned char *str) {
		DEBUG_LOG("_mbslwr(%p)\n", str);
		if (!str) {
			return nullptr;
		}
		for (unsigned char *p = str; *p; ++p) {
			*p = static_cast<unsigned char>(std::tolower(*p));
		}
		return str;
	}

	unsigned char* WIN_ENTRY _mbsupr(unsigned char *str) {
		DEBUG_LOG("_mbsupr(%p)\n", str);
		if (!str) {
			return nullptr;
		}
		for (unsigned char *p = str; *p; ++p) {
			*p = static_cast<unsigned char>(std::toupper(*p));
		}
		return str;
	}

	unsigned char *WIN_ENTRY _mbsinc_l(const unsigned char *str, void *) {
		DEBUG_LOG("_mbsinc_l(%p)\n", str);
		return _mbsinc(str);
	}

	unsigned char *WIN_ENTRY _mbsdec_l(const unsigned char *start, const unsigned char *current, void *locale) {
		DEBUG_LOG("_mbsdec_l(%p, %p, %p)\n", start, current, locale);
		return _mbsdec(start, current);
	}

	int WIN_ENTRY _mbsncmp(const unsigned char *lhs, const unsigned char *rhs, size_t count) {
		DEBUG_LOG("_mbsncmp(%s, %s, %zu)\n", lhs, rhs, count);
		if (!lhs || !rhs) {
			return (lhs == rhs) ? 0 : (lhs ? 1 : -1);
		}
		return std::strncmp(reinterpret_cast<const char *>(lhs), reinterpret_cast<const char *>(rhs), count);
	}

	size_t WIN_ENTRY _mbsspn(const unsigned char *str, const unsigned char *set) {
		DEBUG_LOG("_mbsspn(%s, %s)\n", str, set);
		if (!str || !set) {
			return 0;
		}
		return std::strspn(reinterpret_cast<const char *>(str), reinterpret_cast<const char *>(set));
	}

	int WIN_ENTRY _ismbcdigit(unsigned int ch) {
		DEBUG_LOG("_ismbcdigit(%d)\n", ch);
		if (ch <= 0xFF) {
			return std::isdigit(static_cast<unsigned char>(ch)) ? 1 : 0;
		}
		return 0;
	}

	int WIN_ENTRY _stricmp(const char *lhs, const char *rhs) {
		DEBUG_LOG("_stricmp(%s, %s)\n", lhs, rhs);
		if (!lhs || !rhs) {
			return (lhs == rhs) ? 0 : (lhs ? 1 : -1);
		}
		return strcasecmp(lhs, rhs);
	}

	int WIN_ENTRY _strnicmp(const char *lhs, const char *rhs, size_t count) {
		DEBUG_LOG("_strnicmp(%s, %s, %zu)\n", lhs, rhs, count);
		if (!lhs || !rhs) {
			return (lhs == rhs) ? 0 : (lhs ? 1 : -1);
		}
		return strncasecmp(lhs, rhs, count);
	}

	int WIN_ENTRY _memicmp(const void *lhs, const void *rhs, size_t count) {
		DEBUG_LOG("_memicmp(%p, %p, %zu)\n", lhs, rhs, count);
		if (!lhs || !rhs) {
			return (lhs == rhs) ? 0 : (lhs ? 1 : -1);
		}
		const auto *a = static_cast<const unsigned char *>(lhs);
		const auto *b = static_cast<const unsigned char *>(rhs);
		for (size_t i = 0; i < count; ++i) {
			const auto ca = static_cast<unsigned char>(std::tolower(a[i]));
			const auto cb = static_cast<unsigned char>(std::tolower(b[i]));
			if (ca != cb) {
				return (ca < cb) ? -1 : 1;
			}
		}
		return 0;
	}

	int WIN_ENTRY _vsnprintf(char *buffer, size_t count, const char *format, va_list args) {
		DEBUG_LOG("_vsnprintf(%p, %zu, %s, %p)\n", buffer, count, format, args);
		if (!buffer || !format) {
			errno = EINVAL;
			return -1;
		}
		int result = vsnprintf(buffer, count, format, args);
		if (result < 0) {
			return -1;
		}
		if (static_cast<size_t>(result) >= count) {
			buffer[count ? count - 1 : 0] = '\0';
			return -1;
		}
		return result;
	}

	int WIN_ENTRY _snprintf(char *buffer, size_t count, const char *format, ...) {
		DEBUG_LOG("_snprintf(%p, %zu, %s, ...)\n", buffer, count, format);
		va_list args;
		va_start(args, format);
		int result = _vsnprintf(buffer, count, format, args);
		va_end(args);
		return result;
	}

	int WIN_ENTRY sprintf(char *buffer, const char *format, ...) {
		DEBUG_LOG("sprintf(%p, %s, ...)\n", buffer, format);
		va_list args;
		va_start(args, format);
		int result = ::vsprintf(buffer, format, args);
		va_end(args);
		return result;
	}

	int WIN_ENTRY printf(const char *format, ...) {
		DEBUG_LOG("printf(%s, ...)\n", format);
		va_list args;
		va_start(args, format);
		int result = ::vprintf(format, args);
		va_end(args);
		return result;
	}

	int WIN_ENTRY sscanf(const char *buffer, const char *format, ...) {
		DEBUG_LOG("sscanf(%p, %p, ...)\n", buffer, format);
		va_list args;
		va_start(args, format);
		int result = ::vsscanf(buffer, format, args);
		va_end(args);
		return result;
	}

	char *WIN_ENTRY fgets(char *str, int count, FILE *stream) {
		DEBUG_LOG("fgets(%p, %d, %p)\n", str, count, stream);
		if (!str || count <= 0) {
			return nullptr;
		}
		FILE *host = mapToHostFile(stream);
		return ::fgets(str, count, host);
	}

	size_t WIN_ENTRY fread(void *buffer, size_t size, size_t count, FILE *stream) {
		DEBUG_LOG("fread(%p, %zu, %zu, %p)\n", buffer, size, count, stream);
		FILE *host = mapToHostFile(stream);
		return ::fread(buffer, size, count, host);
	}

	FILE *WIN_ENTRY _fsopen(const char *filename, const char *mode, int shflag) {
		DEBUG_LOG("_fsopen(%s, %s, %d)\n", filename ? filename : "(null)", mode ? mode : "(null)", shflag);
		(void)shflag;
		if (!filename || !mode) {
			errno = EINVAL;
			return nullptr;
		}
		auto hostPath = files::pathFromWindows(filename);
		return ::fopen(hostPath.c_str(), mode);
	}

	int WIN_ENTRY _sopen(const char *path, int oflag, int shflag, int pmode) {
		DEBUG_LOG("_sopen(%s, %d, %d, %d)\n", path ? path : "(null)", oflag, shflag, pmode);
		(void)shflag;
		if (!path) {
			errno = EINVAL;
			return -1;
		}
		auto hostPath = files::pathFromWindows(path);
		int flags = oflag;
		flags &= ~O_BINARY;
		return ::open(hostPath.c_str(), flags, pmode);
	}

	int WIN_ENTRY _read(int fd, void *buffer, unsigned int count) {
		DEBUG_LOG("_read(%d, %p, %u)\n", fd, buffer, count);
		return static_cast<int>(::read(fd, buffer, count));
	}

	int WIN_ENTRY _close(int fd) {
		DEBUG_LOG("_close(%d)\n", fd);
		return ::close(fd);
	}

	long WIN_ENTRY _lseek(int fd, long offset, int origin) {
		DEBUG_LOG("_lseek(%d, %ld, %d)\n", fd, offset, origin);
		off_t result = ::lseek(fd, static_cast<off_t>(offset), origin);
		return static_cast<long>(result);
	}

	int WIN_ENTRY _unlink(const char *path) {
		DEBUG_LOG("_unlink(%s)\n", path ? path : "(null)");
		if (!path) {
			errno = EINVAL;
			return -1;
		}
		auto hostPath = files::pathFromWindows(path);
		return ::unlink(hostPath.c_str());
	}

	int WIN_ENTRY _utime(const char *path, const _utimbuf *times) {
		DEBUG_LOG("_utime(%s, %p)\n", path ? path : "(null)", times);
		if (!path) {
			errno = EINVAL;
			return -1;
		}
		auto hostPath = files::pathFromWindows(path);
		if (!times) {
			return ::utime(hostPath.c_str(), nullptr);
		}
		utimbuf native{static_cast<time_t>(times->actime), static_cast<time_t>(times->modtime)};
		return ::utime(hostPath.c_str(), &native);
	}

	int WIN_ENTRY _chsize(int fd, long size) {
		DEBUG_LOG("_chsize(%d, %ld)\n", fd, size);
		return ::ftruncate(fd, static_cast<off_t>(size));
	}

	char* WIN_ENTRY strncpy(char *dest, const char *src, size_t count) {
		DEBUG_LOG("strncpy(%p, %s, %zu)\n", dest, src ? src : "(null)", count);
		return std::strncpy(dest, src, count);
	}

	char* WIN_ENTRY strpbrk(const char *str, const char *accept) {
		const char *result = std::strpbrk(str, accept);
		DEBUG_LOG("strpbrk(%s, %s) -> %p\n", str ? str : "(null)", accept ? accept : "(null)", result);
		return result ? const_cast<char *>(result) : nullptr;
	}

	char* WIN_ENTRY strstr(const char *haystack, const char *needle) {
		const char *result = std::strstr(haystack, needle);
		DEBUG_LOG("strstr(%s, %s) -> %p\n", haystack ? haystack : "(null)", needle ? needle : "(null)", result);
		return result ? const_cast<char *>(result) : nullptr;
	}

	char* WIN_ENTRY strrchr(const char *str, int ch) {
		DEBUG_LOG("strrchr(%s, %c)\n", str ? str : "(null)", ch);
		const char *result = std::strrchr(str, ch);
		return result ? const_cast<char *>(result) : nullptr;
	}

	char* WIN_ENTRY strtok(char *str, const char *delim) {
		DEBUG_LOG("strtok(%p, %s)\n", str, delim ? delim : "(null)");
		return std::strtok(str, delim);
	}

	long WIN_ENTRY _adj_fdiv_r(long value) {
		DEBUG_LOG("STUB: _adj_fdiv_r(%ld)\n", value);
		return value;
	}

	void WIN_ENTRY _adjust_fdiv(long n) {
		DEBUG_LOG("STUB: _adjust_fdiv(%ld)\n", n);
		(void)n;
	}

	int WIN_ENTRY _ftime(struct _timeb *timeptr) {
		DEBUG_LOG("_ftime(%p)\n", timeptr);
		if (!timeptr) {
			errno = EINVAL;
			return -1;
		}
		struct timeval tv;
		if (gettimeofday(&tv, nullptr) != 0) {
			return -1;
		}
		timeptr->time = tv.tv_sec;
		timeptr->millitm = static_cast<unsigned short>(tv.tv_usec / 1000);
		timeptr->timezone = 0;
		timeptr->dstflag = 0;
		return 0;
	}

	unsigned long WIN_ENTRY _ultoa(unsigned long value, char *str, int radix) {
		DEBUG_LOG("_ultoa(%lu, %s, %d)\n", value, str ? str : "(null)", radix);
		if (!str || radix < 2 || radix > 36) {
			errno = EINVAL;
			return 0;
		}
		char buffer[65];
		char *cursor = buffer + sizeof(buffer);
		*--cursor = '\0';
		if (value == 0) {
			*--cursor = '0';
		}
		while (value > 0) {
			unsigned long digit = value % static_cast<unsigned long>(radix);
			value /= static_cast<unsigned long>(radix);
			*--cursor = static_cast<char>(digit < 10 ? '0' + digit : 'A' + (digit - 10));
		}
		std::strcpy(str, cursor);
		return static_cast<unsigned long>(std::strlen(str));
	}

	char* WIN_ENTRY _ltoa(long value, char *str, int radix) {
		DEBUG_LOG("_ltoa(%ld, %s, %d)\n", value, str ? str : "(null)", radix);
		if (!str || radix < 2 || radix > 36) {
			errno = EINVAL;
			return nullptr;
		}
		bool negative = value < 0;
		unsigned long absValue = negative ? static_cast<unsigned long>(-value) : static_cast<unsigned long>(value);
		char buffer[65];
		unsigned long length = _ultoa(absValue, buffer, radix);
		std::string result;
		if (negative) {
			result.push_back('-');
		}
		result.append(buffer, buffer + length);
		std::strcpy(str, result.c_str());
		return str;
	}

	char* WIN_ENTRY _makepath(char *path, const char *drive, const char *dir, const char *fname, const char *ext) {
		if (!path) {
			return nullptr;
		}
		std::string result;
		if (drive && drive[0]) {
			result.append(drive);
			if (result.back() != ':') {
				result.push_back(':');
			}
		}
		if (dir && dir[0]) {
			result.append(dir);
			char last = result.empty() ? '\0' : result.back();
			if (last != '/' && last != '\\') {
				result.push_back('\\');
			}
		}
		if (fname && fname[0]) {
			result.append(fname);
		}
		if (ext && ext[0]) {
			if (ext[0] != '.') {
				result.push_back('.');
			}
			result.append(ext);
		}
		DEBUG_LOG("_makepath(%p, %s, %s, %s, %s) -> %s\n", path, drive ? drive : "(null)", dir ? dir : "(null)",
				  fname ? fname : "(null)", ext ? ext : "(null)", result.c_str());
		std::strcpy(path, result.c_str());
		return path;
	}

	char* WIN_ENTRY _fullpath(char *absPath, const char *relPath, size_t maxLength) {
		DEBUG_LOG("_fullpath(%p, %s, %zu)\n", absPath, relPath ? relPath : "(null)", maxLength);
		if (!relPath) {
			errno = EINVAL;
			return nullptr;
		}
		std::filesystem::path hostPath = files::pathFromWindows(relPath);
		std::filesystem::path resolved = hostPath;
		if (!hostPath.is_absolute()) {
			resolved = std::filesystem::absolute(hostPath);
		}
		std::string winPath = files::pathToWindows(resolved);
		if (absPath) {
			if (winPath.size() + 1 > maxLength) {
				errno = ERANGE;
				return nullptr;
			}
			std::strcpy(absPath, winPath.c_str());
			return absPath;
		}
		char *result = static_cast<char *>(std::malloc(winPath.size() + 1));
		if (!result) {
			errno = ENOMEM;
			return nullptr;
		}
		DEBUG_LOG("-> %s\n", winPath.c_str());
		std::strcpy(result, winPath.c_str());
		return result;
	}

	int WIN_ENTRY _putenv(const char *envString) {
		DEBUG_LOG("_putenv(%s)\n", envString ? envString : "(null)");
		if (!envString) {
			errno = EINVAL;
			return -1;
		}
		std::string entry(envString);
		if (entry.find('=') == std::string::npos) {
			errno = EINVAL;
			return -1;
		}
		auto &storage = putenvStorage();
		storage.push_back(entry);
		char *stored = storage.back().data();
		return ::putenv(stored);
	}

	char *WIN_ENTRY _mktemp(char *templateName) {
		DEBUG_LOG("_mktemp(%s)\n", templateName);
		if (!templateName) {
			errno = EINVAL;
			return nullptr;
		}
		size_t originalLen = std::strlen(templateName);
		std::string hostTemplate = files::pathFromWindows(templateName).string();
		if (hostTemplate.empty()) {
			hostTemplate = templateName;
		}
		std::vector<char> mutableTemplate(hostTemplate.begin(), hostTemplate.end());
		mutableTemplate.push_back('\0');
		int fd = mkstemp(mutableTemplate.data());
		if (fd == -1) {
			templateName[0] = '\0';
			return templateName;
		}
		::close(fd);
		::unlink(mutableTemplate.data());
		std::string hostResult(mutableTemplate.data());
		std::string winResult = files::pathToWindows(std::filesystem::path(hostResult));
		std::strncpy(templateName, winResult.c_str(), originalLen);
		templateName[originalLen] = '\0';
		DEBUG_LOG("-> %s\n", templateName);
		return templateName;
	}

	int WIN_ENTRY _except_handler3(void *record, void *frame, void *context, void *dispatch) {
		DEBUG_LOG("_except_handler3(%p, %p, %p, %p)\n", record, frame, context, dispatch);
		return _except_handler4_common(record, frame, context, dispatch);
	}

	int WIN_ENTRY getchar() {
		VERBOSE_LOG("getchar()\n");
		return std::getchar();
	}

	time_t WIN_ENTRY time(time_t *t) {
		DEBUG_LOG("time(%p)\n", t);
		time_t result = std::time(nullptr);
		if (t) {
			*t = result;
		}
		return result;
	}

	char *WIN_ENTRY __unDName(char *outputString, const char *mangledName, int maxStringLength,
							  void *(*allocFunc)(size_t), void (*freeFunc)(void *), unsigned short) {
		DEBUG_LOG("STUB: __unDName(%p, %s, %d, %p, %p)\n", outputString, mangledName ? mangledName : "(null)",
				  maxStringLength, allocFunc, freeFunc);
		(void)allocFunc;
		(void)freeFunc;
		if (outputString && maxStringLength > 0) {
			outputString[0] = '\0';
			return outputString;
		}
		return nullptr;
	}

	char* WIN_ENTRY setlocale(int category, const char *locale){
		DEBUG_LOG("setlocale(%d, %s)\n", category, locale ? locale : "(null)");
		char *result = std::setlocale(category, locale);
		if (result) {
			refreshMbCurMax();
		}
		return result;
	}

	int WIN_ENTRY _wdupenv_s(uint16_t **buffer, size_t *numberOfElements, const uint16_t *varname){
		DEBUG_LOG("_wdupenv_s(%p, %p, %s)\n", buffer, numberOfElements, wideStringToString(varname).c_str());
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
		DEBUG_LOG("_wgetenv_s(%p, %p, %zu, %s)\n", pReturnValue, buffer, numberOfElements,
				  wideStringToString(varname).c_str());
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

	size_t WIN_ENTRY strlen(const char *str) {
		VERBOSE_LOG("strlen(%s)\n", str);
		return ::strlen(str);
	}

	int WIN_ENTRY strcmp(const char *lhs, const char *rhs) {
		VERBOSE_LOG("strcmp(%s, %s)\n", lhs, rhs);
		return ::strcmp(lhs, rhs); 
	}

	int WIN_ENTRY strncmp(const char *lhs, const char *rhs, size_t count) {
		VERBOSE_LOG("strncmp(%s, %s, %zu)\n", lhs, rhs, count);
		return ::strncmp(lhs, rhs, count); 
	}

	void WIN_ENTRY _exit(int status) {
		DEBUG_LOG("_exit(%d)\n", status);
		_Exit(status);
	}

	int WIN_ENTRY strcpy_s(char *dest, size_t dest_size, const char *src) {
		VERBOSE_LOG("strcpy_s(%p, %zu, %s)\n", dest, dest_size, src);
		if (!dest || !src || dest_size == 0) {
			return 22;
		}

		size_t src_len = ::strlen(src);
		if (src_len + 1 > dest_size) {
			dest[0] = 0;
			return 34;
		}

		std::memcpy(dest, src, src_len + 1);
		return 0;
	}

	int WIN_ENTRY strcat_s(char *dest, size_t numberOfElements, const char *src) {
		DEBUG_LOG("strcat_s(%p, %zu, %s)\n", dest, numberOfElements, src);
		if (!dest || !src || numberOfElements == 0) {
			return 22;
		}

		size_t dest_len = ::strlen(dest);
		size_t src_len = ::strlen(src);
		if (dest_len + src_len + 1 > numberOfElements) {
			dest[0] = 0;
			return 34;
		}

		std::memcpy(dest + dest_len, src, src_len + 1);
		return 0;
	}

	int WIN_ENTRY strncpy_s(char *dest, size_t dest_size, const char *src, size_t count) {
		DEBUG_LOG("strncpy_s(%p, %zu, %s, %zu)\n", dest, dest_size, src, count);
		constexpr size_t TRUNCATE = static_cast<size_t>(-1);
		constexpr int STRUNCATE = 80;

		if (!dest || dest_size == 0) {
			return 22;
		}

		if (!src) {
			dest[0] = 0;
			return count == 0 ? 0 : 22;
		}

		if (count == 0) {
			dest[0] = 0;
			return 0;
		}

		if (count == TRUNCATE) {
			size_t src_len = ::strlen(src);
			if (src_len + 1 > dest_size) {
				size_t copy_len = dest_size > 0 ? dest_size - 1 : 0;
				if (copy_len > 0) {
					std::memcpy(dest, src, copy_len);
				}
				dest[copy_len] = '\0';
				return STRUNCATE;
			}
			std::memcpy(dest, src, src_len + 1);
			return 0;
		}

		size_t src_len = ::strlen(src);
		size_t copy_len = count < src_len ? count : src_len;
		if (copy_len >= dest_size) {
			dest[0] = 0;
			return 34;
		}

		if (copy_len > 0) {
			std::memcpy(dest, src, copy_len);
		}
		dest[copy_len] = '\0';
		return 0;
	}

	char *WIN_ENTRY _strdup(const char *strSource) {
		DEBUG_LOG("_strdup(%s)\n", strSource);
		if (!strSource) {
			return nullptr;
		}

		size_t length = ::strlen(strSource);
		auto *copy = static_cast<char *>(std::malloc(length + 1));
		if (!copy) {
			return nullptr;
		}

		std::memcpy(copy, strSource, length + 1);
		return copy;
	}

	unsigned long WIN_ENTRY strtoul(const char *str, char **endptr, int base) {
		VERBOSE_LOG("strtoul(%s, %p, %d)\n", str, endptr, base);
		return ::strtoul(str, endptr, base);
	}

	void* WIN_ENTRY malloc(size_t size){
		VERBOSE_LOG("malloc(%zu)\n", size);
		return std::malloc(size);
	}

	void* WIN_ENTRY calloc(size_t count, size_t size){
		VERBOSE_LOG("calloc(%zu, %zu)\n", count, size);
		return std::calloc(count, size);
	}

	void* WIN_ENTRY realloc(void *ptr, size_t size) {
		VERBOSE_LOG("realloc(%p, %zu)\n", ptr, size);
		return std::realloc(ptr, size);
	}

	void* WIN_ENTRY _malloc_crt(size_t size) {
		VERBOSE_LOG("_malloc_crt(%zu)\n", size);
		return std::malloc(size);
	}

	void WIN_ENTRY _lock(int locknum) {
		VERBOSE_LOG("_lock(%d)\n", locknum);
		if (locknum < 0 || static_cast<size_t>(locknum) >= LOCK_TABLE_SIZE) {
			DEBUG_LOG("_lock: unsupported lock %d\n", locknum);
			return;
		}
		lockTable()[static_cast<size_t>(locknum)].lock();
	}

	void WIN_ENTRY _unlock(int locknum) {
		VERBOSE_LOG("_unlock(%d)\n", locknum);
		if (locknum < 0 || static_cast<size_t>(locknum) >= LOCK_TABLE_SIZE) {
			DEBUG_LOG("_unlock: unsupported lock %d\n", locknum);
			return;
		}
		lockTable()[static_cast<size_t>(locknum)].unlock();
	}

	_onexit_t WIN_ENTRY __dllonexit(_onexit_t func, _PVFV **pbegin, _PVFV **pend) {
		DEBUG_LOG("__dllonexit(%p, %p, %p)\n", func, pbegin, pend);
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
		VERBOSE_LOG("free(%p)\n", ptr);
		std::free(ptr);
	}

	void* WIN_ENTRY memcpy(void *dest, const void *src, size_t count) {
		VERBOSE_LOG("memcpy(%p, %p, %zu)\n", dest, src, count);
		return std::memcpy(dest, src, count);
	}

	void* WIN_ENTRY memmove(void *dest, const void *src, size_t count) {
		VERBOSE_LOG("memmove(%p, %p, %zu)\n", dest, src, count);
		return std::memmove(dest, src, count);
	}

	int WIN_ENTRY memcmp(const void *lhs, const void *rhs, size_t count) {
		VERBOSE_LOG("memcmp(%p, %p, %zu)\n", lhs, rhs, count);
		return std::memcmp(lhs, rhs, count);
	}

	void WIN_ENTRY qsort(void *base, size_t num, size_t size, int (*compar)(const void *, const void *)) {
		DEBUG_LOG("qsort(%p, %zu, %zu, %p)\n", base, num, size, compar);
		std::qsort(base, num, size, compar);
	}

	int WIN_ENTRY fflush(FILE *stream) {
		DEBUG_LOG("fflush(%p)\n", stream);
		if (!stream) {
			return std::fflush(nullptr);
		}
		FILE *host = mapToHostFile(stream);
		return std::fflush(host);
	}

	int WIN_ENTRY vfwprintf(FILE *stream, const uint16_t *format, va_list args) {
		DEBUG_LOG("vfwprintf(%p, %s, ...)\n", stream, wideStringToString(format).c_str());
		FILE *host = mapToHostFile(stream ? stream : stdout);
		std::wstring fmt;
		if (format) {
			for (const uint16_t *ptr = format; *ptr; ++ptr) {
				fmt.push_back(static_cast<wchar_t>(*ptr));
			}
		}
		fmt.push_back(L'\0');
		return std::vfwprintf(host, fmt.c_str(), args);
	}

	FILE *WIN_ENTRY fopen(const char *filename, const char *mode) {
		DEBUG_LOG("fopen(%s, %s)\n", filename ? filename : "(null)", mode ? mode : "(null)");
		return std::fopen(filename, mode);
	}

	int WIN_ENTRY _dup2(int fd1, int fd2) {
		VERBOSE_LOG("_dup2(%d, %d)\n", fd1, fd2);
		return dup2(fd1, fd2);
	}

	int WIN_ENTRY _isatty(int fd) {
		VERBOSE_LOG("_isatty(%d)\n", fd);
		return isatty(fd);
	}

	int WIN_ENTRY fseek(FILE *stream, long offset, int origin) {
		VERBOSE_LOG("fseek(%p, %ld, %d)\n", stream, offset, origin);
		return std::fseek(stream, offset, origin);
	}

	long WIN_ENTRY ftell(FILE *stream) {
		VERBOSE_LOG("ftell(%p)\n", stream);
		return std::ftell(stream);
	}

	int WIN_ENTRY feof(FILE *stream) {
		VERBOSE_LOG("feof(%p)\n", stream);
		return std::feof(stream);
	}

	int WIN_ENTRY fputws(const uint16_t *str, FILE *stream) {
		DEBUG_LOG("fputws(%s, %p)\n", wideStringToString(str).c_str(), stream);
		std::wstring temp;
		if (str) {
			for (const uint16_t *cursor = str; *cursor; ++cursor) {
				temp.push_back(static_cast<wchar_t>(*cursor));
			}
		}
		return std::fputws(temp.c_str(), stream);
	}

	int WIN_ENTRY _cputws(const uint16_t *string) {
		DEBUG_LOG("_cputws(%s)\n", wideStringToString(string).c_str());
		return fputws(string, stdout);
	}

	uint16_t* WIN_ENTRY fgetws(uint16_t *buffer, int size, FILE *stream) {
		DEBUG_LOG("fgetws(%p, %d, %p)\n", buffer, size, stream);
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
		VERBOSE_LOG("fgetwc(%p)\n", stream);
		return std::fgetwc(stream);
	}

	int WIN_ENTRY _wfopen_s(FILE **stream, const uint16_t *filename, const uint16_t *mode) {
		DEBUG_LOG("_wfopen_s(%p, %s, %s)\n", stream, wideStringToString(filename).c_str(),
				  wideStringToString(mode).c_str());
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
		VERBOSE_LOG("_wcsicmp(%s, %s)\n", wideStringToString(lhs).c_str(), wideStringToString(rhs).c_str());
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
		DEBUG_LOG("_wmakepath_s(%p, %zu, %s, %s, %s, %s)\n", path, sizeInWords, wideStringToString(drive).c_str(),
				  wideStringToString(dir).c_str(), wideStringToString(fname).c_str(), wideStringToString(ext).c_str());
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

		DEBUG_LOG("-> %s\n", wideStringToString(reinterpret_cast<const uint16_t*>(result.c_str())).c_str());

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
		DEBUG_LOG("_wputenv_s(%p, %p)\n", varname, value);
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
		VERBOSE_LOG("wcsspn(%p, %p)\n", str1, str2);
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
		VERBOSE_LOG("_wtol(%p)\n", str);
		return wstrtol(str, nullptr, 10);
	}

	int WIN_ENTRY _wcsupr_s(uint16_t *str, size_t size) {
		VERBOSE_LOG("_wcsupr_s(%p, %zu)\n", str, size);
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
		VERBOSE_LOG("_wcslwr_s(%p, %zu)\n", str, size);
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
		VERBOSE_LOG("towlower(%d)\n", ch);
		return static_cast<wint_t>(std::towlower(static_cast<wchar_t>(ch)));
	}

	unsigned int WIN_ENTRY _mbctolower(unsigned int ch) {
		VERBOSE_LOG("_mbctolower(%u)\n", ch);
		if (ch <= 0xFF) {
			unsigned char byte = static_cast<unsigned char>(ch);
			unsigned char lowered = static_cast<unsigned char>(std::tolower(static_cast<int>(byte)));
			return static_cast<unsigned int>(lowered);
		}
		return ch;
	}

	int WIN_ENTRY toupper(int ch) {
		VERBOSE_LOG("toupper(%d)\n", ch);
		return std::toupper(ch);
	}

	int WIN_ENTRY tolower(int ch) {
		VERBOSE_LOG("tolower(%d)\n", ch);
		return std::tolower(ch);
	}

	int WIN_ENTRY _ftime64_s(void *timeb) {
		DEBUG_LOG("STUB: _ftime64_s(%p)\n", timeb);
		(void)timeb;
		return 0;
	}

	int WIN_ENTRY _crt_debugger_hook(int value) {
		DEBUG_LOG("STUB: _crt_debugger_hook(%d)\n", value);
		(void)value;
		return 0;
	}

	int WIN_ENTRY _configthreadlocale(int mode) {
		DEBUG_LOG("_configthreadlocale(mode=%d)\n", mode);
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

	void WIN_ENTRY __setusermatherr(void* handler) {
		DEBUG_LOG("STUB: __setusermatherr(handler=%p)\n", handler);
		(void)handler;
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
		DEBUG_LOG("vfprintf(stream=%p, format=%s, args=%p)\n", stream, format, args);
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
		DEBUG_LOG("fprintf(%p, %s, ...)\n", stream, format);
		va_list args;
		va_start(args, format);
		int result = msvcrt::vfprintf(stream, format, args);
		va_end(args);
		return result;
	}

	int WIN_ENTRY fputc(int ch, FILE *stream) {
		DEBUG_LOG("fputc(%d, %p)\n", ch, stream);
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
		DEBUG_LOG("fwrite(%p, %zu, %zu, %p)\n", buffer, size, count, stream);
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
		DEBUG_LOG("strerror(%d)\n", errnum);
		return std::strerror(errnum);
	}

	char *WIN_ENTRY strchr(const char *str, int character) {
		VERBOSE_LOG("strchr(%s, %d)\n", str, character);
		return const_cast<char *>(std::strchr(str, character));
	}

	struct lconv *WIN_ENTRY localeconv() {
		VERBOSE_LOG("localeconv()\n");
		return std::localeconv();
	}

	using SignalHandler = void (*)(int);

	SignalHandler WIN_ENTRY signal(int sig, SignalHandler handler) {
		DEBUG_LOG("signal(%d, %p)\n", sig, handler);
		if (sig != SIGABRT && sig != SIGFPE && sig != SIGILL && sig != SIGINT &&
			sig != SIGSEGV && sig != SIGTERM) {
			DEBUG_LOG("signal: unsupported signal %d\n", sig);
			errno = EINVAL;
			return SIG_ERR;
		}
		return std::signal(sig, handler);
	}

	size_t WIN_ENTRY wcslen(const uint16_t *str) {
		VERBOSE_LOG("wcslen(%p)\n", str);
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
		VERBOSE_LOG("atoi(%s)\n", str);
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
		DEBUG_LOG("_invoke_watson(...)\n");
		abort_and_log("_invoke_watson");
	}

	void WIN_ENTRY terminateShim() {
		abort_and_log("terminate");
	}

	int WIN_ENTRY _purecall() {
		abort_and_log("_purecall");
		return 0;
	}

	int WIN_ENTRY _except_handler4_common(void *, void *, void *, void *) {
		DEBUG_LOG("STUB: _except_handler4_common\n");
		return 0;
	}

	long WIN_ENTRY _XcptFilter(unsigned long code, void *) {
		DEBUG_LOG("STUB: _XcptFilter(%lu)\n", code);
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

		std::string exePathStr(exe_path);
		if (_pgmptr) {
			free(_pgmptr);
		}
		_pgmptr = ::strdup(exePathStr.c_str());

		std::vector<uint16_t> wStr = stringToWideString(exePathStr.c_str());
		if (_wpgmptr) {
			delete[] _wpgmptr;
		}
		_wpgmptr = new uint16_t[wStr.size() + 1];
		std::copy(wStr.begin(), wStr.end(), _wpgmptr);
		_wpgmptr[wStr.size()] = 0;

		*pValue = _wpgmptr;
		return 0;
	}

	char** WIN_ENTRY __p__pgmptr() {
		return &_pgmptr;
	}

	int WIN_ENTRY _wsplitpath_s(const uint16_t * path, uint16_t * drive, size_t driveNumberOfElements, uint16_t *dir, size_t dirNumberOfElements,
		uint16_t * fname, size_t nameNumberOfElements, uint16_t * ext, size_t extNumberOfElements){
		if(!path){
			return 22;
		}
		else {
			std::string path_str = wideStringToString(path);
		}
		DEBUG_LOG("_wsplitpath_s(path=%p, drive=%p, driveNumberOfElements=%zu, dir=%p, dirNumberOfElements=%zu, "
			"fname=%p, nameNumberOfElements=%zu, ext=%p, extNumberOfElements=%zu)\n",
			path, drive, driveNumberOfElements, dir, dirNumberOfElements, fname, nameNumberOfElements, ext, extNumberOfElements);

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
		DEBUG_LOG("wcsncpy_s(%p, %zu, %p, %zu)\n", strDest, numberOfElements, strSource, count);

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
		VERBOSE_LOG(" -> %s\n", wideStringToString(strDest).c_str());
		return 0;
	}

	int WIN_ENTRY wcsncat_s(uint16_t *strDest, size_t numberOfElements, const uint16_t *strSource, size_t count){
		std::string dst_str = wideStringToString(strDest);
		std::string src_str = wideStringToString(strSource);
		DEBUG_LOG("wscncat_s(%p, %zu, %p, %zu)\n", strDest, numberOfElements, strSource, count);

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
		VERBOSE_LOG(" -> %s\n", wideStringToString(strDest).c_str());
		return 0;
	}

	int WIN_ENTRY _itow_s(int value, uint16_t *buffer, size_t size, int radix){
		VERBOSE_LOG("_itow_s(%d, %p, %zu, %d)\n", value, buffer, size, radix);
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
		VERBOSE_LOG("_wtoi(%p)\n", str);
		return wstrtol(str, nullptr, 10);
	}

	int WIN_ENTRY _ltoa_s(long value, char *buffer, size_t sizeInChars, int radix) {
		VERBOSE_LOG("_ltoa_s(%ld, %p, %zu, %d)\n", value, buffer, sizeInChars, radix);
		if (!buffer || sizeInChars == 0) {
			return 22;
		}
		if (radix < 2 || radix > 36) {
			buffer[0] = 0;
			return 22;
		}

		bool isNegative = (value < 0) && (radix == 10);
		uint64_t magnitude = isNegative ? static_cast<uint64_t>(-(int64_t)value) : static_cast<uint64_t>(static_cast<int64_t>(value));
		char temp[65];
		size_t index = 0;
		do {
			uint64_t digit = magnitude % static_cast<uint64_t>(radix);
			temp[index++] = static_cast<char>((digit < 10) ? ('0' + digit) : ('a' + (digit - 10)));
			magnitude /= static_cast<uint64_t>(radix);
		} while (magnitude != 0 && index < sizeof(temp));

		if (isNegative) {
			temp[index++] = '-';
		}

		size_t required = index + 1; // include null terminator
		if (required > sizeInChars) {
			buffer[0] = 0;
			return 34;
		}

		for (size_t i = 0; i < index; ++i) {
			buffer[i] = temp[index - i - 1];
		}
		buffer[index] = '\0';
		return 0;
	}

	int WIN_ENTRY wcscpy_s(uint16_t *dest, size_t dest_size, const uint16_t *src){
		std::string src_str = wideStringToString(src);
		VERBOSE_LOG("wcscpy_s(%p, %zu, %p)\n", dest, dest_size, src);
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

	int WIN_ENTRY swprintf_s(uint16_t *buffer, size_t sizeOfBuffer, const uint16_t *format, ...) {
		VERBOSE_LOG("swprintf_s(%p, %zu, %p, ...)\n", buffer, sizeOfBuffer, format);
		if (!buffer || sizeOfBuffer == 0 || !format) {
			errno = EINVAL;
			return EINVAL;
		}
		std::wstring fmt;
		for (const uint16_t *ptr = format; *ptr; ++ptr) {
			fmt.push_back(static_cast<wchar_t>(*ptr));
		}
		fmt.push_back(L'\0');
		std::vector<wchar_t> temp(sizeOfBuffer);
		va_list args;
		va_start(args, format);
		int written = std::vswprintf(temp.data(), temp.size(), fmt.c_str(), args);
		va_end(args);
		if (written < 0 || static_cast<size_t>(written) >= sizeOfBuffer) {
			buffer[0] = 0;
			errno = ERANGE;
			return ERANGE;
		}
		for (int i = 0; i <= written; ++i) {
			buffer[i] = static_cast<uint16_t>(temp[static_cast<size_t>(i)]);
		}
		return written;
	}

	int WIN_ENTRY swscanf_s(const uint16_t *buffer, const uint16_t *format, ...) {
		VERBOSE_LOG("swscanf_s(%p, %p, ...)\n", buffer, format);
		if (!buffer || !format) {
			errno = EINVAL;
			return EOF;
		}
		std::wstring bufW;
		for (const uint16_t *ptr = buffer; *ptr; ++ptr) {
			bufW.push_back(static_cast<wchar_t>(*ptr));
		}
		bufW.push_back(L'\0');
		std::wstring fmt;
		for (const uint16_t *ptr = format; *ptr; ++ptr) {
			fmt.push_back(static_cast<wchar_t>(*ptr));
		}
		fmt.push_back(L'\0');
		va_list args;
		va_start(args, format);
		int result = std::vswscanf(bufW.c_str(), fmt.c_str(), args);
		va_end(args);
		return result;
	}

	int* WIN_ENTRY _get_osfhandle(int fd){
		DEBUG_LOG("STUB: _get_osfhandle(%d)\n", fd);
		return (int*)fd;
	}

	int WIN_ENTRY _write(int fd, const void* buffer, unsigned int count) {
		VERBOSE_LOG("_write(fd=%d, buffer=%p, count=%u)\n", fd, buffer, count);
		return (int)write(fd, buffer, count);
	}

	void WIN_ENTRY exit(int status) {
		VERBOSE_LOG("exit(%d)\n", status);
		_Exit(status);
	}

	int WIN_ENTRY wcsncmp(const uint16_t *string1, const uint16_t *string2, size_t count) {
		VERBOSE_LOG("wcsncmp(%p, %p, %zu)\n", string1, string2, count);
		return wstrncmp(string1, string2, count);
	}

	int WIN_ENTRY _vswprintf_c_l(uint16_t* buffer, size_t size, const uint16_t* format, ...) {
		DEBUG_LOG("_vswprintf_c_l(%p, %zu, %p, ...)\n", buffer, size, format);
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
		VERBOSE_LOG("wcsstr(%p, %p)\n", dest, src);
		return wstrstr(dest, src);
	}

	int WIN_ENTRY iswspace(uint32_t w){
		VERBOSE_LOG("iswspace(%u)\n", w);
		return std::iswspace(w);
	}

	int WIN_ENTRY iswdigit(uint32_t w){
		VERBOSE_LOG("iswdigit(%u)\n", w);
		return std::iswdigit(w);
	}

	const uint16_t* WIN_ENTRY wcschr(const uint16_t* str, uint16_t c){
		VERBOSE_LOG("wcschr(%p, %u)\n", str, c);
		return wstrchr(str, c);
	}

	const uint16_t* WIN_ENTRY wcsrchr(const uint16_t *str, uint16_t c){
		VERBOSE_LOG("wcsrchr(%p, %u)\n", str, c);
		return wstrrchr(str, c);
	}

	unsigned long WIN_ENTRY wcstoul(const uint16_t *strSource, uint16_t **endptr, int base){
		VERBOSE_LOG("wcstoul(%p, %p, %d)\n", strSource, endptr, base);
		return wstrtoul(strSource, endptr, base);
	}

	FILE* WIN_ENTRY _wfsopen(const uint16_t* filename, const uint16_t* mode, int shflag){
		if (!filename || !mode) return nullptr;
		std::string fname_str = wideStringToString(filename);
		std::string mode_str = wideStringToString(mode);
		DEBUG_LOG("_wfsopen(%s, %s)\n", fname_str.c_str(), mode_str.c_str());

		(void)shflag;
		return fopen(fname_str.c_str(), mode_str.c_str());
	}

	int WIN_ENTRY puts(const char *str) {
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

	int WIN_ENTRY fclose(FILE* stream){
		VERBOSE_LOG("fclose(%p)\n", stream);
		return ::fclose(stream);
	}

	int WIN_ENTRY _flushall(){
		DEBUG_LOG("_flushall()\n");
		int count = 0;

		if (msvcrt::fflush(stdin) == 0) count++;
		if (msvcrt::fflush(stdout) == 0) count++;
		if (msvcrt::fflush(stderr) == 0) count++;

		return count;
	}

	int* WIN_ENTRY _errno() {
		VERBOSE_LOG("_errno()\n");
		return &errno;
	}

	intptr_t WIN_ENTRY _wspawnvp(int mode, const uint16_t* cmdname, const uint16_t* const * argv) {
		if (!cmdname || !argv) {
			errno = EINVAL;
			return -1;
		}

		std::string command = wideStringToString(cmdname);
		DEBUG_LOG("_wspawnvp(%d, %s)\n", mode, command.c_str());

		std::vector<std::string> argStorage;
		argStorage.emplace_back(command);
		for (const uint16_t *const *cursor = argv; *cursor; ++cursor) {
			argStorage.emplace_back(wideStringToString(*cursor));
		}

		auto resolved = processes::resolveExecutable(command, false);
		if (!resolved) {
			errno = ENOENT;
			DEBUG_LOG("-> failed to resolve executable for %s\n", command.c_str());
			return -1;
		}
		DEBUG_LOG("-> resolved to %s\n", resolved->c_str());

		pid_t pid = -1;
		int spawnResult = processes::spawnWithArgv(*resolved, argStorage, &pid);
		if (spawnResult != 0) {
			errno = spawnResult;
			DEBUG_LOG("-> spawnWithArgv failed: %d\n", spawnResult);
			return -1;
		}
		DEBUG_LOG("-> spawned pid %d\n", pid);

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

	intptr_t WIN_ENTRY _spawnvp(int mode, const char *cmdname, const char * const *argv) {
		if (!cmdname || !argv) {
			errno = EINVAL;
			return -1;
		}

		std::string command(cmdname);
		DEBUG_LOG("_spawnvp(%d, %s)\n", mode, command.c_str());

		std::vector<std::string> argStorage;
		argStorage.emplace_back(command);
		for (const char * const *cursor = argv; *cursor; ++cursor) {
			argStorage.emplace_back(*cursor);
		}

		auto resolved = processes::resolveExecutable(command, false);
		if (!resolved) {
			errno = ENOENT;
			DEBUG_LOG("-> failed to resolve executable for %s\n", command.c_str());
			return -1;
		}
		DEBUG_LOG("-> resolved to %s\n", resolved->c_str());

		pid_t pid = -1;
		int spawnResult = processes::spawnWithArgv(*resolved, argStorage, &pid);
		if (spawnResult != 0) {
			errno = spawnResult;
			DEBUG_LOG("-> spawnWithArgv failed: %d\n", spawnResult);
			return -1;
		}
		DEBUG_LOG("-> spawned pid %d\n", pid);

		constexpr int P_WAIT = 0;
		constexpr int P_DETACH = 2;

		if (mode == P_WAIT) {
			int status = 0;
			if (waitpid(pid, &status, 0) == -1) {
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

		return static_cast<intptr_t>(pid);
	}

	int WIN_ENTRY _wunlink(const uint16_t *filename){
		std::string str = wideStringToString(filename);
		DEBUG_LOG("_wunlink(%s)\n", str.c_str());
		return unlink(str.c_str());
	}

	uint16_t* WIN_ENTRY _wfullpath(uint16_t* absPath, const uint16_t* relPath, size_t maxLength){
		std::string relPathStr = wideStringToString(relPath);
		DEBUG_LOG("_wfullpath(%s, %zu)\n", relPathStr.c_str(), maxLength);
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
	if (strcmp(name, "__iob_func") == 0) return (void *) msvcrt::__iob_func;
	if (strcmp(name, "_exit") == 0) return (void *) msvcrt::_exit;
	if (strcmp(name, "__p__fmode") == 0) return (void *) msvcrt::__p__fmode;
	if (strcmp(name, "__p__commode") == 0) return (void *) msvcrt::__p__commode;
	if (strcmp(name, "_initterm") == 0) return (void *)msvcrt::_initterm;
	if (strcmp(name, "_initterm_e") == 0) return (void *)msvcrt::_initterm_e;
	if (strcmp(name, "_controlfp") == 0) return (void *)msvcrt::_controlfp;
	if (strcmp(name, "_controlfp_s") == 0) return (void *)msvcrt::_controlfp_s;
	if (strcmp(name, "__p___initenv") == 0) return (void *)msvcrt::__p___initenv;
	if (strcmp(name, "_onexit") == 0) return (void*)msvcrt::_onexit;
	if (strcmp(name, "__getmainargs") == 0) return (void*)msvcrt::__getmainargs;
	if (strcmp(name, "__wgetmainargs") == 0) return (void*)msvcrt::__wgetmainargs;
	if (strcmp(name, "setlocale") == 0) return (void*)msvcrt::setlocale;
	if (strcmp(name, "__mb_cur_max") == 0) return (void *)&msvcrt::mbCurMaxValue;
	if (strcmp(name, "__p__mbctype") == 0) return (void *)msvcrt::__p__mbctype;
	if (strcmp(name, "__p__pctype") == 0) return (void *)msvcrt::__p__pctype;
	if (strcmp(name, "__p___mb_cur_max") == 0) return (void *)msvcrt::__p___mb_cur_max;
	if (strcmp(name, "_isctype") == 0) return (void *)msvcrt::_isctype;
	if (strcmp(name, "__unDName") == 0) return (void *)msvcrt::__unDName;
	if (strcmp(name, "__setusermatherr") == 0) return (void *)msvcrt::__setusermatherr;
	if (strcmp(name, "_wdupenv_s") == 0) return (void*)msvcrt::_wdupenv_s;
	if (strcmp(name, "strlen") == 0) return (void *)msvcrt::strlen;
	if (strcmp(name, "strcmp") == 0) return (void *)msvcrt::strcmp;
	if (strcmp(name, "strncmp") == 0) return (void *)msvcrt::strncmp;
	if (strcmp(name, "strcat") == 0) return (void *)msvcrt::strcat;
	if (strcmp(name, "strcpy") == 0) return (void *)msvcrt::strcpy;
	if (strcmp(name, "strcpy_s") == 0) return (void *)msvcrt::strcpy_s;
	if (strcmp(name, "strcat_s") == 0) return (void *)msvcrt::strcat_s;
	if (strcmp(name, "strncpy_s") == 0) return (void *)msvcrt::strncpy_s;
	if (strcmp(name, "_strdup") == 0) return (void *)msvcrt::_strdup;
	if (strcmp(name, "strncpy") == 0) return (void *)msvcrt::strncpy;
	if (strcmp(name, "strpbrk") == 0) return (void *)msvcrt::strpbrk;
	if (strcmp(name, "strstr") == 0) return (void *)msvcrt::strstr;
	if (strcmp(name, "strrchr") == 0) return (void *)msvcrt::strrchr;
	if (strcmp(name, "strtok") == 0) return (void *)msvcrt::strtok;
	if (strcmp(name, "sprintf") == 0) return (void *)msvcrt::sprintf;
	if (strcmp(name, "printf") == 0) return (void *)msvcrt::printf;
	if (strcmp(name, "sscanf") == 0) return (void *)msvcrt::sscanf;
	if (strcmp(name, "strtoul") == 0) return (void *)msvcrt::strtoul;
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
	if (strcmp(name, "__p__pgmptr") == 0) return (void*)msvcrt::__p__pgmptr;
	if (strcmp(name, "_splitpath") == 0) return (void*)msvcrt::_splitpath;
	if (strcmp(name, "memset") == 0) return (void*)msvcrt::memset;
	if (strcmp(name, "memcpy") == 0) return (void*)msvcrt::memcpy;
	if (strcmp(name, "memmove") == 0) return (void*)msvcrt::memmove;
	if (strcmp(name, "memcmp") == 0) return (void*)msvcrt::memcmp;
	if (strcmp(name, "qsort") == 0) return (void*)msvcrt::qsort;
	if (strcmp(name, "fflush") == 0) return (void*)msvcrt::fflush;
	if (strcmp(name, "fopen") == 0) return (void*)msvcrt::fopen;
	if (strcmp(name, "fseek") == 0) return (void*)msvcrt::fseek;
	if (strcmp(name, "ftell") == 0) return (void*)msvcrt::ftell;
	if (strcmp(name, "feof") == 0) return (void*)msvcrt::feof;
	if (strcmp(name, "fgetws") == 0) return (void*)msvcrt::fgetws;
	if (strcmp(name, "fgetwc") == 0) return (void*)msvcrt::fgetwc;
	if (strcmp(name, "fgets") == 0) return (void*)msvcrt::fgets;
	if (strcmp(name, "fputws") == 0) return (void*)msvcrt::fputws;
	if (strcmp(name, "_cputws") == 0) return (void*)msvcrt::_cputws;
	if (strcmp(name, "vfwprintf") == 0) return (void*)msvcrt::vfwprintf;
	if (strcmp(name, "_wfopen_s") == 0) return (void*)msvcrt::_wfopen_s;
	if (strcmp(name, "wcsspn") == 0) return (void*)msvcrt::wcsspn;
	if (strcmp(name, "_fileno") == 0) return (void*)msvcrt::_fileno;
	if (strcmp(name, "_wtol") == 0) return (void*)msvcrt::_wtol;
	if (strcmp(name, "_wcsupr_s") == 0) return (void*)msvcrt::_wcsupr_s;
	if (strcmp(name, "_wcslwr_s") == 0) return (void*)msvcrt::_wcslwr_s;
	if (strcmp(name, "_dup2") == 0) return (void*)msvcrt::_dup2;
	if (strcmp(name, "_isatty") == 0) return (void*)msvcrt::_isatty;
	if (strcmp(name, "swprintf_s") == 0) return (void*)msvcrt::swprintf_s;
	if (strcmp(name, "swscanf_s") == 0) return (void*)msvcrt::swscanf_s;
	if (strcmp(name, "towlower") == 0) return (void*)msvcrt::towlower;
	if (strcmp(name, "toupper") == 0) return (void*)msvcrt::toupper;
	if (strcmp(name, "tolower") == 0) return (void*)msvcrt::tolower;
	if (strcmp(name, "setbuf") == 0) return (void*)msvcrt::setbuf;
	if (strcmp(name, "_mbctolower") == 0) return (void*)msvcrt::_mbctolower;
	if (strcmp(name, "_ismbcspace") == 0) return (void*)msvcrt::_ismbcspace;
	if (strcmp(name, "_ismbcdigit") == 0) return (void*)msvcrt::_ismbcdigit;
	if (strcmp(name, "_ismbblead") == 0) return (void*)msvcrt::_ismbblead;
	if (strcmp(name, "_ismbbtrail") == 0) return (void*)msvcrt::_ismbbtrail;
	if (strcmp(name, "_mbccpy") == 0) return (void*)msvcrt::_mbccpy;
	if (strcmp(name, "_mbsinc") == 0) return (void*)msvcrt::_mbsinc;
	if (strcmp(name, "_mbsdec") == 0) return (void*)msvcrt::_mbsdec;
	if (strcmp(name, "_mbclen") == 0) return (void*)msvcrt::_mbclen;
	if (strcmp(name, "_mbscmp") == 0) return (void*)msvcrt::_mbscmp;
	if (strcmp(name, "_mbsicmp") == 0) return (void*)msvcrt::_mbsicmp;
	if (strcmp(name, "_mbsstr") == 0) return (void*)msvcrt::_mbsstr;
	if (strcmp(name, "_mbschr") == 0) return (void*)msvcrt::_mbschr;
	if (strcmp(name, "_mbsrchr") == 0) return (void*)msvcrt::_mbsrchr;
	if (strcmp(name, "_mbslwr") == 0) return (void*)msvcrt::_mbslwr;
	if (strcmp(name, "_mbsupr") == 0) return (void*)msvcrt::_mbsupr;
	if (strcmp(name, "_mbsspn") == 0) return (void*)msvcrt::_mbsspn;
	if (strcmp(name, "_mbsncmp") == 0) return (void*)msvcrt::_mbsncmp;
	if (strcmp(name, "_ftime64_s") == 0) return (void*)msvcrt::_ftime64_s;
	if (strcmp(name, "_crt_debugger_hook") == 0) return (void*)msvcrt::_crt_debugger_hook;
	if (strcmp(name, "_configthreadlocale") == 0) return (void*)msvcrt::_configthreadlocale;
	if (strcmp(name, "_amsg_exit") == 0) return (void*)msvcrt::_amsg_exit;
	if (strcmp(name, "_invoke_watson") == 0) return (void*)msvcrt::_invoke_watson;
	if (strcmp(name, "_except_handler4_common") == 0) return (void*)msvcrt::_except_handler4_common;
	if (strcmp(name, "_except_handler3") == 0) return (void*)msvcrt::_except_handler3;
	if (strcmp(name, "_XcptFilter") == 0) return (void*)msvcrt::_XcptFilter;
	if (strcmp(name, "?terminate@@YAXXZ") == 0) return (void*)msvcrt::terminateShim;
	if (strcmp(name, "_purecall") == 0) return (void*)msvcrt::_purecall;
	if (strcmp(name, "wcsncpy_s") == 0) return (void*)msvcrt::wcsncpy_s;
	if (strcmp(name, "wcsncat_s") == 0) return (void*)msvcrt::wcsncat_s;
	if (strcmp(name, "_itow_s") == 0) return (void*)msvcrt::_itow_s;
	if (strcmp(name, "_wtoi") == 0) return (void*)msvcrt::_wtoi;
	if (strcmp(name, "_ltoa_s") == 0) return (void*)msvcrt::_ltoa_s;
	if (strcmp(name, "wcscpy_s") == 0) return (void*)msvcrt::wcscpy_s;
	if (strcmp(name, "_get_osfhandle") == 0) return (void*)msvcrt::_get_osfhandle;
	if (strcmp(name, "_write") == 0) return (void*)msvcrt::_write;
	if (strcmp(name, "_read") == 0) return (void*)msvcrt::_read;
	if (strcmp(name, "_close") == 0) return (void*)msvcrt::_close;
	if (strcmp(name, "_lseek") == 0) return (void*)msvcrt::_lseek;
	if (strcmp(name, "_chsize") == 0) return (void*)msvcrt::_chsize;
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
	if (strcmp(name, "_access") == 0) return (void*)msvcrt::_access;
	if (strcmp(name, "_dup2") == 0) return (void*)msvcrt::_dup2;
	if (strcmp(name, "_wfsopen") == 0) return (void*)msvcrt::_wfsopen;
	if (strcmp(name, "_fsopen") == 0) return (void*)msvcrt::_fsopen;
	if (strcmp(name, "_sopen") == 0) return (void*)msvcrt::_sopen;
	if (strcmp(name, "fputws") == 0) return (void*)msvcrt::fputws;
	if (strcmp(name, "puts") == 0) return (void*)msvcrt::puts;
	if (strcmp(name, "fclose") == 0) return (void*)msvcrt::fclose;
	if (strcmp(name, "_flushall") == 0) return (void*)msvcrt::_flushall;
	if (strcmp(name, "_errno") == 0) return (void*)msvcrt::_errno;
	if (strcmp(name, "_getmbcp") == 0) return (void*)msvcrt::_getmbcp;
	if (strcmp(name, "_setmbcp") == 0) return (void*)msvcrt::_setmbcp;
	if (strcmp(name, "_wspawnvp") == 0) return (void*)msvcrt::_wspawnvp;
	if (strcmp(name, "_wunlink") == 0) return (void*)msvcrt::_wunlink;
	if (strcmp(name, "_wfullpath") == 0) return (void*)msvcrt::_wfullpath;
	if (strcmp(name, "_cexit") == 0) return (void*)msvcrt::_cexit;
	if (strcmp(name, "_iob") == 0) return (void*)msvcrt::standardIobEntries();
	if (strcmp(name, "__p__iob") == 0) return (void*)msvcrt::__p__iob;
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
	if (strcmp(name, "fread") == 0) return (void*)msvcrt::fread;
	if (strcmp(name, "_unlink") == 0) return (void*)msvcrt::_unlink;
	if (strcmp(name, "_utime") == 0) return (void*)msvcrt::_utime;
	if (strcmp(name, "_ultoa") == 0) return (void*)msvcrt::_ultoa;
	if (strcmp(name, "_ltoa") == 0) return (void*)msvcrt::_ltoa;
	if (strcmp(name, "_makepath") == 0) return (void*)msvcrt::_makepath;
	if (strcmp(name, "_fullpath") == 0) return (void*)msvcrt::_fullpath;
	if (strcmp(name, "_vsnprintf") == 0) return (void*)msvcrt::_vsnprintf;
	if (strcmp(name, "_snprintf") == 0) return (void*)msvcrt::_snprintf;
	if (strcmp(name, "_adj_fdiv_r") == 0) return (void*)msvcrt::_adj_fdiv_r;
	if (strcmp(name, "_adjust_fdiv") == 0) return (void*)msvcrt::_adjust_fdiv;
	if (strcmp(name, "_memicmp") == 0) return (void*)msvcrt::_memicmp;
	if (strcmp(name, "_stricmp") == 0) return (void*)msvcrt::_stricmp;
	if (strcmp(name, "_strnicmp") == 0) return (void*)msvcrt::_strnicmp;
	if (strcmp(name, "_putenv") == 0) return (void*)msvcrt::_putenv;
	if (strcmp(name, "_mktemp") == 0) return (void*)msvcrt::_mktemp;
	if (strcmp(name, "_spawnvp") == 0) return (void*)msvcrt::_spawnvp;
	if (strcmp(name, "_ftime") == 0) return (void*)msvcrt::_ftime;
	if (strcmp(name, "getchar") == 0) return (void*)msvcrt::getchar;
	if (strcmp(name, "time") == 0) return (void*)msvcrt::time;
	return nullptr;
}

wibo::Module lib_msvcrt = {
	(const char *[]){
		"msvcrt",
		"msvcrt40",
		"msvcr70",
		"msvcr100",
		nullptr,
	},
	resolveByName,
	nullptr,
};
