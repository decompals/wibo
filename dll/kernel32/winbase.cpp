#include "winbase.h"

#include "errors.h"
#include "files.h"
#include "handles.h"
#include "internal.h"
#include "strutil.h"

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <limits>
#include <mimalloc.h>
#include <mutex>
#include <string>
#include <unordered_map>
#include <sys/mman.h>
#include <sys/statvfs.h>
#include <system_error>

namespace {

constexpr UINT GMEM_MOVEABLE = 0x0002;
constexpr UINT GMEM_ZEROINIT = 0x0040;
constexpr UINT GMEM_MODIFY = 0x0080;

constexpr UINT LMEM_MOVEABLE = 0x0002;
constexpr UINT LMEM_ZEROINIT = 0x0040;

constexpr ATOM kMinIntegerAtom = 0x0001;
constexpr ATOM kMaxIntegerAtom = 0xBFFF;
constexpr ATOM kMinStringAtom = 0xC000;
constexpr ATOM kMaxStringAtom = 0xFFFF;

struct AtomData {
	uint16_t refCount = 0;
	std::string original;
};

struct AtomTable {
	std::mutex mutex;
	std::unordered_map<std::string, ATOM> stringToAtom;
	std::unordered_map<ATOM, AtomData> atomToData;
	ATOM nextStringAtom = kMinStringAtom;
};

AtomTable &localAtomTable() {
	static AtomTable table;
	return table;
}

ATOM allocateStringAtomLocked(AtomTable &table) {
	constexpr unsigned int kRange = static_cast<unsigned int>(kMaxStringAtom - kMinStringAtom + 1);
	unsigned int startOffset = 0;
	if (table.nextStringAtom >= kMinStringAtom && table.nextStringAtom <= kMaxStringAtom) {
		startOffset = static_cast<unsigned int>(table.nextStringAtom - kMinStringAtom);
	}
	for (unsigned int i = 0; i < kRange; ++i) {
		unsigned int offset = (startOffset + i) % kRange;
		ATOM candidate = static_cast<ATOM>(kMinStringAtom + offset);
		if (table.atomToData.find(candidate) == table.atomToData.end()) {
			table.nextStringAtom = static_cast<ATOM>(candidate + 1);
			if (table.nextStringAtom > kMaxStringAtom) {
				table.nextStringAtom = kMinStringAtom;
			}
			return candidate;
		}
	}
	return 0;
}

bool tryHandleIntegerAtomPointer(const void *ptr, ATOM &atomOut) {
	uintptr_t value = reinterpret_cast<uintptr_t>(ptr);
	if ((value >> 16) != 0) {
		return false;
	}
	ATOM maybeAtom = static_cast<ATOM>(value & 0xFFFFu);
	if (maybeAtom < kMinIntegerAtom || maybeAtom > kMaxIntegerAtom) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		atomOut = 0;
		return true;
	}
	wibo::lastError = ERROR_SUCCESS;
	atomOut = maybeAtom;
	return true;
}

ATOM findAtomByNormalizedKey(const std::string &normalizedKey) {
	auto &table = localAtomTable();
	std::lock_guard lk(table.mutex);
	auto it = table.stringToAtom.find(normalizedKey);
	if (it == table.stringToAtom.end()) {
		wibo::lastError = ERROR_FILE_NOT_FOUND;
		return 0;
	}
	wibo::lastError = ERROR_SUCCESS;
	return it->second;
}

ATOM tryParseIntegerAtomString(const std::string &value, bool &handled) {
	handled = false;
	if (value.empty() || value[0] != '#') {
		return 0;
	}
	char *end = nullptr;
	unsigned long parsed = std::strtoul(value.c_str() + 1, &end, 10);
	if (end == value.c_str() + 1 || *end != '\0') {
		return 0;
	}
	handled = true;
	if (parsed < kMinIntegerAtom || parsed > kMaxIntegerAtom) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	wibo::lastError = ERROR_SUCCESS;
	return static_cast<ATOM>(parsed);
}

ATOM findAtomByString(const std::string &value) {
	bool handledInteger = false;
	ATOM atom = tryParseIntegerAtomString(value, handledInteger);
	if (handledInteger) {
		return atom;
	}
	std::string normalized = stringToLower(value);
	return findAtomByNormalizedKey(normalized);
}

ATOM addAtomByString(const std::string &value) {
	bool handledInteger = false;
	ATOM atom = tryParseIntegerAtomString(value, handledInteger);
	if (handledInteger) {
		return atom;
	}
	if (value.empty() || value.size() > 255) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	std::string normalized = stringToLower(value);
	auto &table = localAtomTable();
	std::lock_guard lk(table.mutex);
	auto existing = table.stringToAtom.find(normalized);
	if (existing != table.stringToAtom.end()) {
		auto dataIt = table.atomToData.find(existing->second);
		if (dataIt != table.atomToData.end() && dataIt->second.refCount < std::numeric_limits<uint16_t>::max()) {
			dataIt->second.refCount++;
		}
		wibo::lastError = ERROR_SUCCESS;
		return existing->second;
	}
	ATOM newAtom = allocateStringAtomLocked(table);
	if (newAtom == 0) {
		wibo::lastError = ERROR_NOT_ENOUGH_MEMORY;
		return 0;
	}
	AtomData data;
	data.refCount = 1;
	data.original = value;
	table.stringToAtom.emplace(std::move(normalized), newAtom);
	table.atomToData.emplace(newAtom, std::move(data));
	wibo::lastError = ERROR_SUCCESS;
	return newAtom;
}

void *doAlloc(UINT dwBytes, bool zero) {
	if (dwBytes == 0) {
		dwBytes = 1;
	}
	void *ret = mi_malloc_aligned(dwBytes, 8);
	if (ret && zero) {
		std::memset(ret, 0, mi_usable_size(ret));
	}
	return ret;
}

void *doRealloc(void *mem, UINT dwBytes, bool zero) {
	if (dwBytes == 0) {
		dwBytes = 1;
	}
	size_t oldSize = mi_usable_size(mem);
	void *ret = mi_realloc_aligned(mem, dwBytes, 8);
	size_t newSize = mi_usable_size(ret);
	if (ret && zero && newSize > oldSize) {
		std::memset(static_cast<char *>(ret) + oldSize, 0, newSize - oldSize);
	}
	return ret;
}

bool tryGetCurrentDirectoryPath(std::string &outPath) {
	std::error_code ec;
	std::filesystem::path cwd = std::filesystem::current_path(ec);
	if (ec) {
		errno = ec.value();
		kernel32::setLastErrorFromErrno();
		return false;
	}
	outPath = files::pathToWindows(cwd);
	return true;
}

bool computeLongWindowsPath(const std::string &inputPath, std::string &longPath) {
	bool hasTrailingSlash = false;
	if (!inputPath.empty()) {
		char last = inputPath.back();
		hasTrailingSlash = (last == '\\' || last == '/');
	}

	auto hostPath = files::pathFromWindows(inputPath.c_str());
	if (hostPath.empty()) {
		wibo::lastError = ERROR_PATH_NOT_FOUND;
		return false;
	}

	std::error_code ec;
	if (!std::filesystem::exists(hostPath, ec)) {
		wibo::lastError = ERROR_FILE_NOT_FOUND;
		return false;
	}

	longPath = files::pathToWindows(hostPath);
	if (hasTrailingSlash && !longPath.empty() && longPath.back() != '\\') {
		longPath.push_back('\\');
	}
	wibo::lastError = ERROR_SUCCESS;
	return true;
}

bool resolveDiskFreeSpaceStat(const char *rootPathName, struct statvfs &outBuf, std::string &resolvedPath) {
	std::filesystem::path hostPath;
	if (rootPathName && *rootPathName) {
		hostPath = files::pathFromWindows(rootPathName);
	} else {
		std::error_code ec;
		hostPath = std::filesystem::current_path(ec);
		if (ec) {
			wibo::lastError = ERROR_PATH_NOT_FOUND;
			return false;
		}
	}
	if (hostPath.empty()) {
		wibo::lastError = ERROR_PATH_NOT_FOUND;
		return false;
	}

	hostPath = hostPath.lexically_normal();
	if (hostPath.empty()) {
		hostPath = std::filesystem::path("/");
	}

	std::error_code ec;
	if (!hostPath.is_absolute()) {
		auto abs = std::filesystem::absolute(hostPath, ec);
		if (ec) {
			wibo::lastError = ERROR_PATH_NOT_FOUND;
			return false;
		}
		hostPath = abs;
	}

	std::filesystem::path queryPath = hostPath;
	while (true) {
		std::string query = queryPath.empty() ? std::string("/") : queryPath.string();
		if (query.empty()) {
			query = "/";
		}
		if (statvfs(query.c_str(), &outBuf) == 0) {
			resolvedPath = query;
			wibo::lastError = ERROR_SUCCESS;
			return true;
		}

		int savedErrno = errno;
		if (savedErrno != ENOENT && savedErrno != ENOTDIR) {
			errno = savedErrno;
			kernel32::setLastErrorFromErrno();
			return false;
		}

		std::filesystem::path parent = queryPath.parent_path();
		if (parent == queryPath) {
			errno = savedErrno;
			kernel32::setLastErrorFromErrno();
			return false;
		}
		if (parent.empty()) {
			parent = std::filesystem::path("/");
		}
		queryPath = parent;
	}
}

constexpr DWORD kComputerNameLength = 8;
constexpr DWORD kComputerNameRequiredSize = kComputerNameLength + 1;
constexpr const char kComputerNameAnsi[] = "COMPNAME";
const uint16_t kComputerNameWide[] = {u'C', u'O', u'M', u'P', u'N', u'A', u'M', u'E', 0};

} // namespace

namespace kernel32 {

ATOM WIN_FUNC AddAtomA(LPCSTR lpString) {
	WIN_API_SEGMENT_GUARD();
	ATOM atom = 0;
	if (tryHandleIntegerAtomPointer(lpString, atom)) {
		DEBUG_LOG("AddAtomA(int:%u)\n", atom);
		return atom;
	}
	DEBUG_LOG("AddAtomA(%s)\n", lpString ? lpString : "<null>");
	if (!lpString) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	size_t len = strnlen(lpString, 256);
	if (len == 0 || len >= 256) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	std::string value(lpString, len);
	ATOM result = addAtomByString(value);
	DEBUG_LOG("AddAtomA -> %u (lastError=%u)\n", result, wibo::lastError);
	return result;
}

ATOM WIN_FUNC AddAtomW(LPCWSTR lpString) {
	WIN_API_SEGMENT_GUARD();
	ATOM atom = 0;
	if (tryHandleIntegerAtomPointer(lpString, atom)) {
		DEBUG_LOG("AddAtomW(int:%u)\n", atom);
		return atom;
	}
	if (!lpString) {
		DEBUG_LOG("AddAtomW(<null>)\n");
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	size_t len = wstrnlen(reinterpret_cast<const uint16_t *>(lpString), 256);
	if (len == 0 || len >= 256) {
		DEBUG_LOG("AddAtomW(invalid length)\n");
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	std::string value = wideStringToString(reinterpret_cast<const uint16_t *>(lpString), static_cast<int>(len));
	DEBUG_LOG("AddAtomW(%s)\n", value.c_str());
	ATOM result = addAtomByString(value);
	DEBUG_LOG("AddAtomW -> %u (lastError=%u)\n", result, wibo::lastError);
	return result;
}

ATOM WIN_FUNC FindAtomA(LPCSTR lpString) {
	WIN_API_SEGMENT_GUARD();
	ATOM atom = 0;
	if (tryHandleIntegerAtomPointer(lpString, atom)) {
		DEBUG_LOG("FindAtomA(int:%u)\n", atom);
		return atom;
	}
	DEBUG_LOG("FindAtomA(%s)\n", lpString ? lpString : "<null>");
	if (!lpString) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	size_t len = strnlen(lpString, 256);
	if (len == 0 || len >= 256) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	std::string value(lpString, len);
	ATOM result = findAtomByString(value);
	DEBUG_LOG("FindAtomA -> %u (lastError=%u)\n", result, wibo::lastError);
	return result;
}

ATOM WIN_FUNC FindAtomW(LPCWSTR lpString) {
	WIN_API_SEGMENT_GUARD();
	ATOM atom = 0;
	if (tryHandleIntegerAtomPointer(lpString, atom)) {
		DEBUG_LOG("FindAtomW(int:%u)\n", atom);
		return atom;
	}
	if (!lpString) {
		DEBUG_LOG("FindAtomW(<null>)\n");
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	size_t len = wstrnlen(reinterpret_cast<const uint16_t *>(lpString), 256);
	if (len == 0 || len >= 256) {
		DEBUG_LOG("FindAtomW(invalid length)\n");
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	std::string value = wideStringToString(reinterpret_cast<const uint16_t *>(lpString), static_cast<int>(len));
	DEBUG_LOG("FindAtomW(%s)\n", value.c_str());
	ATOM result = findAtomByString(value);
	DEBUG_LOG("FindAtomW -> %u (lastError=%u)\n", result, wibo::lastError);
	return result;
}

UINT WIN_FUNC GetAtomNameA(ATOM nAtom, LPSTR lpBuffer, int nSize) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetAtomNameA(%u, %p, %d)\n", nAtom, lpBuffer, nSize);
	if (!lpBuffer || nSize <= 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	std::string value;
	if (nAtom >= kMinIntegerAtom && nAtom <= kMaxIntegerAtom) {
		value = '#';
		value += std::to_string(nAtom);
	} else {
		auto &table = localAtomTable();
		std::lock_guard lk(table.mutex);
		auto it = table.atomToData.find(nAtom);
		if (it == table.atomToData.end()) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return 0;
		}
		value = it->second.original;
	}
	if (value.size() + 1 > static_cast<size_t>(nSize)) {
		wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
		return 0;
	}
	std::memcpy(lpBuffer, value.c_str(), value.size());
	lpBuffer[value.size()] = '\0';
	wibo::lastError = ERROR_SUCCESS;
	UINT written = static_cast<UINT>(value.size());
	DEBUG_LOG("GetAtomNameA -> %u (lastError=%u)\n", written, wibo::lastError);
	return written;
}

UINT WIN_FUNC GetAtomNameW(ATOM nAtom, LPWSTR lpBuffer, int nSize) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetAtomNameW(%u, %p, %d)\n", nAtom, lpBuffer, nSize);
	if (!lpBuffer || nSize <= 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	std::string narrow;
	if (nAtom >= kMinIntegerAtom && nAtom <= kMaxIntegerAtom) {
		narrow = '#';
		narrow += std::to_string(nAtom);
	} else {
		auto &table = localAtomTable();
		std::lock_guard lk(table.mutex);
		auto it = table.atomToData.find(nAtom);
		if (it == table.atomToData.end()) {
			wibo::lastError = ERROR_INVALID_HANDLE;
			return 0;
		}
		narrow = it->second.original;
	}
	auto wide = stringToWideString(narrow.c_str(), narrow.size());
	size_t needed = wide.size();
	if (needed > static_cast<size_t>(nSize)) {
		wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
		return 0;
	}
	std::memcpy(lpBuffer, wide.data(), needed * sizeof(uint16_t));
	if (needed > 0) {
		lpBuffer[needed - 1] = 0;
	}
	wibo::lastError = ERROR_SUCCESS;
	UINT written = static_cast<UINT>(needed ? needed - 1 : 0);
	DEBUG_LOG("GetAtomNameW -> %u (lastError=%u)\n", written, wibo::lastError);
	return written;
}

UINT WIN_FUNC SetHandleCount(UINT uNumber) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("SetHandleCount(%u)\n", uNumber);
	(void)uNumber;
	return 0x3FFE;
}

DWORD WIN_FUNC FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer,
							  DWORD nSize, va_list *Arguments) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("FormatMessageA(%u, %p, %u, %u, %p, %u, %p)\n", dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer,
			  nSize, Arguments);

	if (dwFlags & 0x00000100) {
		// FORMAT_MESSAGE_ALLOCATE_BUFFER
	} else if (dwFlags & 0x00002000) {
		// FORMAT_MESSAGE_ARGUMENT_ARRAY
	} else if (dwFlags & 0x00000800) {
		// FORMAT_MESSAGE_FROM_HMODULE
	} else if (dwFlags & 0x00000400) {
		// FORMAT_MESSAGE_FROM_STRING
	} else if (dwFlags & 0x00001000) {
		// FORMAT_MESSAGE_FROM_SYSTEM
		std::string message = std::system_category().message(static_cast<int>(dwMessageId));
		size_t length = message.length();
		if (!lpBuffer || nSize == 0) {
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return 0;
		}
		std::strncpy(lpBuffer, message.c_str(), static_cast<size_t>(nSize));
		if (static_cast<size_t>(nSize) <= length) {
			if (static_cast<size_t>(nSize) > 0) {
				lpBuffer[nSize - 1] = '\0';
			}
			wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
			return 0;
		}
		lpBuffer[length] = '\0';
		wibo::lastError = ERROR_SUCCESS;
		return static_cast<DWORD>(length);
	} else if (dwFlags & 0x00000200) {
		// FORMAT_MESSAGE_IGNORE_INSERTS
	} else {
		// unhandled?
	}

	if (lpBuffer && nSize > 0) {
		lpBuffer[0] = '\0';
	}
	wibo::lastError = ERROR_CALL_NOT_IMPLEMENTED;
	return 0;
}

PVOID WIN_FUNC EncodePointer(PVOID Ptr) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("EncodePointer(%p)\n", Ptr);
	return Ptr;
}

PVOID WIN_FUNC DecodePointer(PVOID Ptr) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("DecodePointer(%p)\n", Ptr);
	return Ptr;
}

BOOL WIN_FUNC SetDllDirectoryA(LPCSTR lpPathName) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("SetDllDirectoryA(%s)\n", lpPathName);
	if (!lpPathName || lpPathName[0] == '\0') {
		wibo::clearDllDirectoryOverride();
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	std::filesystem::path hostPath = files::pathFromWindows(lpPathName);
	if (hostPath.empty() || !std::filesystem::exists(hostPath)) {
		wibo::lastError = ERROR_PATH_NOT_FOUND;
		return FALSE;
	}

	wibo::setDllDirectoryOverride(std::filesystem::absolute(hostPath));
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

void tryMarkExecutable(void *mem) {
	if (!mem) {
		return;
	}
	size_t usable = mi_usable_size(mem);
	if (usable == 0) {
		return;
	}
	long pageSize = sysconf(_SC_PAGESIZE);
	if (pageSize <= 0) {
		return;
	}
	uintptr_t start = reinterpret_cast<uintptr_t>(mem);
	uintptr_t alignedStart = start & ~static_cast<uintptr_t>(pageSize - 1);
	uintptr_t end = (start + usable + pageSize - 1) & ~static_cast<uintptr_t>(pageSize - 1);
	size_t length = static_cast<size_t>(end - alignedStart);
	if (length == 0) {
		return;
	}
	mprotect(reinterpret_cast<void *>(alignedStart), length, PROT_READ | PROT_WRITE | PROT_EXEC);
}

BOOL WIN_FUNC IsBadReadPtr(LPCVOID lp, UINT_PTR ucb) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("STUB: IsBadReadPtr(ptr=%p, size=%zu)\n", lp, static_cast<size_t>(ucb));
	if (!lp) {
		return TRUE;
	}
	return FALSE;
}

BOOL WIN_FUNC IsBadWritePtr(LPVOID lp, UINT_PTR ucb) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("STUB: IsBadWritePtr(ptr=%p, size=%zu)\n", lp, static_cast<size_t>(ucb));
	if (!lp && ucb != 0) {
		return TRUE;
	}
	return FALSE;
}

BOOL WIN_FUNC GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetComputerNameA(%p, %p)\n", lpBuffer, nSize);
	if (!nSize || !lpBuffer) {
		if (nSize) {
			*nSize = 0;
		}
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	if (*nSize < kComputerNameRequiredSize) {
		*nSize = kComputerNameRequiredSize;
		wibo::lastError = ERROR_BUFFER_OVERFLOW;
		return FALSE;
	}

	std::strcpy(lpBuffer, kComputerNameAnsi);
	*nSize = kComputerNameLength;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC GetComputerNameW(LPWSTR lpBuffer, LPDWORD nSize) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetComputerNameW(%p, %p)\n", lpBuffer, nSize);
	if (!nSize || !lpBuffer) {
		if (nSize) {
			*nSize = 0;
		}
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	if (*nSize < kComputerNameRequiredSize) {
		*nSize = kComputerNameRequiredSize;
		wibo::lastError = ERROR_BUFFER_OVERFLOW;
		return FALSE;
	}

	wstrncpy(lpBuffer, kComputerNameWide, static_cast<size_t>(kComputerNameRequiredSize));
	*nSize = kComputerNameLength;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

HGLOBAL WIN_FUNC GlobalAlloc(UINT uFlags, SIZE_T dwBytes) {
	WIN_API_SEGMENT_GUARD();
	VERBOSE_LOG("GlobalAlloc(%x, %zu)\n", uFlags, static_cast<size_t>(dwBytes));
	if (uFlags & GMEM_MOVEABLE) {
		// not implemented rn
		assert(0);
		return nullptr;
	}
	bool zero = (uFlags & GMEM_ZEROINIT) != 0;
	return doAlloc(static_cast<UINT>(dwBytes), zero);
}

HGLOBAL WIN_FUNC GlobalFree(HGLOBAL hMem) {
	WIN_API_SEGMENT_GUARD();
	VERBOSE_LOG("GlobalFree(%p)\n", hMem);
	std::free(hMem);
	return nullptr;
}

HGLOBAL WIN_FUNC GlobalReAlloc(HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags) {
	WIN_API_SEGMENT_GUARD();
	VERBOSE_LOG("GlobalReAlloc(%p, %zu, %x)\n", hMem, static_cast<size_t>(dwBytes), uFlags);
	if (uFlags & GMEM_MODIFY) {
		assert(0);
		return nullptr;
	}
	bool zero = (uFlags & GMEM_ZEROINIT) != 0;
	return doRealloc(hMem, static_cast<UINT>(dwBytes), zero);
}

UINT WIN_FUNC GlobalFlags(HGLOBAL hMem) {
	WIN_API_SEGMENT_GUARD();
	VERBOSE_LOG("GlobalFlags(%p)\n", hMem);
	(void)hMem;
	return 0;
}

HLOCAL WIN_FUNC LocalAlloc(UINT uFlags, SIZE_T uBytes) {
	WIN_API_SEGMENT_GUARD();
	VERBOSE_LOG("LocalAlloc(%x, %zu)\n", uFlags, static_cast<size_t>(uBytes));
	bool zero = (uFlags & LMEM_ZEROINIT) != 0;
	if ((uFlags & LMEM_MOVEABLE) != 0) {
		DEBUG_LOG("  ignoring LMEM_MOVEABLE\n");
	}
	void *result = doAlloc(static_cast<UINT>(uBytes), zero);
	if (!result) {
		wibo::lastError = ERROR_NOT_SUPPORTED;
		return nullptr;
	}
	// Legacy Windows applications (pre-NX and DEP) may expect executable memory from LocalAlloc.
	tryMarkExecutable(result);
	DEBUG_LOG("  -> %p\n", result);
	wibo::lastError = ERROR_SUCCESS;
	return result;
}

HLOCAL WIN_FUNC LocalFree(HLOCAL hMem) {
	WIN_API_SEGMENT_GUARD();
	VERBOSE_LOG("LocalFree(%p)\n", hMem);
	// Windows returns NULL on success.
	std::free(hMem);
	wibo::lastError = ERROR_SUCCESS;
	return nullptr;
}

HLOCAL WIN_FUNC LocalReAlloc(HLOCAL hMem, SIZE_T uBytes, UINT uFlags) {
	WIN_API_SEGMENT_GUARD();
	VERBOSE_LOG("LocalReAlloc(%p, %zu, %x)\n", hMem, static_cast<size_t>(uBytes), uFlags);
	bool zero = (uFlags & LMEM_ZEROINIT) != 0;
	if ((uFlags & LMEM_MOVEABLE) != 0) {
		DEBUG_LOG("  ignoring LMEM_MOVEABLE\n");
	}
	void *result = doRealloc(hMem, static_cast<UINT>(uBytes), zero);
	if (!result && uBytes != 0) {
		wibo::lastError = ERROR_NOT_SUPPORTED;
		return nullptr;
	}
	// Legacy Windows applications (pre-NX and DEP) may expect executable memory from LocalReAlloc.
	tryMarkExecutable(result);
	DEBUG_LOG("  -> %p\n", result);
	wibo::lastError = ERROR_SUCCESS;
	return result;
}

HLOCAL WIN_FUNC LocalHandle(LPCVOID pMem) {
	WIN_API_SEGMENT_GUARD();
	VERBOSE_LOG("LocalHandle(%p)\n", pMem);
	return const_cast<LPVOID>(pMem);
}

LPVOID WIN_FUNC LocalLock(HLOCAL hMem) {
	WIN_API_SEGMENT_GUARD();
	VERBOSE_LOG("LocalLock(%p)\n", hMem);
	wibo::lastError = ERROR_SUCCESS;
	return hMem;
}

BOOL WIN_FUNC LocalUnlock(HLOCAL hMem) {
	WIN_API_SEGMENT_GUARD();
	VERBOSE_LOG("LocalUnlock(%p)\n", hMem);
	(void)hMem;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

SIZE_T WIN_FUNC LocalSize(HLOCAL hMem) {
	WIN_API_SEGMENT_GUARD();
	VERBOSE_LOG("LocalSize(%p)\n", hMem);
	return hMem ? mi_usable_size(hMem) : 0;
}

UINT WIN_FUNC LocalFlags(HLOCAL hMem) {
	WIN_API_SEGMENT_GUARD();
	VERBOSE_LOG("LocalFlags(%p)\n", hMem);
	(void)hMem;
	return 0;
}

static constexpr const char *kSystemDirectoryA = "C:\\Windows\\System32";

UINT WIN_FUNC GetSystemDirectoryA(LPSTR lpBuffer, UINT uSize) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetSystemDirectoryA(%p, %u)\n", lpBuffer, uSize);
	if (!lpBuffer) {
		return 0;
	}

	const auto len = std::strlen(kSystemDirectoryA);
	if (uSize < len + 1) {
		return static_cast<UINT>(len + 1);
	}
	std::strcpy(lpBuffer, kSystemDirectoryA);
	return static_cast<UINT>(len);
}

UINT WIN_FUNC GetSystemDirectoryW(LPWSTR lpBuffer, UINT uSize) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetSystemDirectoryW(%p, %u)\n", lpBuffer, uSize);
	if (!lpBuffer) {
		return 0;
	}

	auto wide = stringToWideString(kSystemDirectoryA);
	UINT length = static_cast<UINT>(wide.size() - 1);
	if (uSize < length + 1) {
		return length + 1;
	}
	std::memcpy(lpBuffer, wide.data(), (length + 1) * sizeof(uint16_t));
	return length;
}

UINT WIN_FUNC GetSystemWow64DirectoryA(LPSTR lpBuffer, UINT uSize) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetSystemWow64DirectoryA(%p, %u)\n", lpBuffer, uSize);
	(void)lpBuffer;
	(void)uSize;
	wibo::lastError = ERROR_CALL_NOT_IMPLEMENTED;
	return 0;
}

UINT WIN_FUNC GetSystemWow64DirectoryW(LPWSTR lpBuffer, UINT uSize) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetSystemWow64DirectoryW(%p, %u)\n", lpBuffer, uSize);
	(void)lpBuffer;
	(void)uSize;
	wibo::lastError = ERROR_CALL_NOT_IMPLEMENTED;
	return 0;
}

UINT WIN_FUNC GetWindowsDirectoryA(LPSTR lpBuffer, UINT uSize) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetWindowsDirectoryA(%p, %u)\n", lpBuffer, uSize);
	if (!lpBuffer) {
		return 0;
	}

	const char *windowsDir = "C:\\Windows";
	const auto len = std::strlen(windowsDir);
	if (uSize < len + 1) {
		return static_cast<UINT>(len + 1);
	}
	std::strcpy(lpBuffer, windowsDir);
	return static_cast<UINT>(len);
}

DWORD WIN_FUNC GetCurrentDirectoryA(DWORD nBufferLength, LPSTR lpBuffer) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetCurrentDirectoryA(%u, %p)\n", nBufferLength, lpBuffer);

	std::string path;
	if (!tryGetCurrentDirectoryPath(path)) {
		return 0;
	}

	const DWORD required = static_cast<DWORD>(path.size() + 1);
	if (nBufferLength == 0) {
		return required;
	}
	if (!lpBuffer) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	if (nBufferLength < required) {
		wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
		return required;
	}
	std::memcpy(lpBuffer, path.c_str(), required);
	wibo::lastError = ERROR_SUCCESS;
	return required - 1;
}

DWORD WIN_FUNC GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetCurrentDirectoryW(%u, %p)\n", nBufferLength, lpBuffer);

	std::string path;
	if (!tryGetCurrentDirectoryPath(path)) {
		return 0;
	}
	auto widePath = stringToWideString(path.c_str());
	const DWORD required = static_cast<DWORD>(widePath.size());
	if (nBufferLength == 0) {
		return required;
	}
	if (!lpBuffer) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	if (nBufferLength < required) {
		wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
		return required;
	}
	std::copy(widePath.begin(), widePath.end(), lpBuffer);
	wibo::lastError = ERROR_SUCCESS;
	return required - 1;
}

int WIN_FUNC SetCurrentDirectoryA(LPCSTR lpPathName) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("SetCurrentDirectoryA(%s)\n", lpPathName ? lpPathName : "(null)");
	if (!lpPathName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	auto hostPath = files::pathFromWindows(lpPathName);
	std::error_code ec;
	std::filesystem::current_path(hostPath, ec);
	if (ec) {
		errno = ec.value();
		kernel32::setLastErrorFromErrno();
		return 0;
	}
	wibo::lastError = ERROR_SUCCESS;
	return 1;
}

int WIN_FUNC SetCurrentDirectoryW(LPCWSTR lpPathName) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("SetCurrentDirectoryW\n");
	if (!lpPathName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	std::string path = wideStringToString(lpPathName);
	return SetCurrentDirectoryA(path.c_str());
}

DWORD WIN_FUNC GetLongPathNameA(LPCSTR lpszShortPath, LPSTR lpszLongPath, DWORD cchBuffer) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetLongPathNameA(%s, %p, %u)\n", lpszShortPath ? lpszShortPath : "(null)", lpszLongPath, cchBuffer);
	if (!lpszShortPath) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}

	std::string input(lpszShortPath);
	std::string longPath;
	if (!computeLongWindowsPath(input, longPath)) {
		return 0;
	}

	DWORD required = static_cast<DWORD>(longPath.size() + 1);
	if (cchBuffer == 0) {
		return required;
	}
	if (!lpszLongPath) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	if (cchBuffer < required) {
		wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
		return required;
	}
	std::memcpy(lpszLongPath, longPath.c_str(), required);
	wibo::lastError = ERROR_SUCCESS;
	return required - 1;
}

DWORD WIN_FUNC GetLongPathNameW(LPCWSTR lpszShortPath, LPWSTR lpszLongPath, DWORD cchBuffer) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetLongPathNameW(%p, %p, %u)\n", lpszShortPath, lpszLongPath, cchBuffer);
	if (!lpszShortPath) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	std::string input = wideStringToString(lpszShortPath);
	std::string longPath;
	if (!computeLongWindowsPath(input, longPath)) {
		return 0;
	}
	auto wideLong = stringToWideString(longPath.c_str());
	DWORD required = static_cast<DWORD>(wideLong.size());
	if (cchBuffer == 0) {
		return required;
	}
	if (!lpszLongPath) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	if (cchBuffer < required) {
		wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
		return required;
	}
	std::copy(wideLong.begin(), wideLong.end(), lpszLongPath);
	wibo::lastError = ERROR_SUCCESS;
	return required - 1;
}

BOOL WIN_FUNC GetDiskFreeSpaceA(LPCSTR lpRootPathName, LPDWORD lpSectorsPerCluster, LPDWORD lpBytesPerSector,
								LPDWORD lpNumberOfFreeClusters, LPDWORD lpTotalNumberOfClusters) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetDiskFreeSpaceA(%s)\n", lpRootPathName ? lpRootPathName : "(null)");
	struct statvfs buf{};
	std::string resolvedPath;
	if (!resolveDiskFreeSpaceStat(lpRootPathName, buf, resolvedPath)) {
		return FALSE;
	}

	uint64_t blockSize = buf.f_frsize ? buf.f_frsize : buf.f_bsize;
	if (blockSize == 0) {
		blockSize = 4096;
	}
	unsigned int bytesPerSector = 512;
	if (blockSize % bytesPerSector != 0) {
		bytesPerSector =
			static_cast<unsigned int>(std::min<uint64_t>(blockSize, std::numeric_limits<unsigned int>::max()));
	}
	unsigned int sectorsPerCluster = static_cast<unsigned int>(blockSize / bytesPerSector);
	if (sectorsPerCluster == 0) {
		sectorsPerCluster = 1;
		bytesPerSector =
			static_cast<unsigned int>(std::min<uint64_t>(blockSize, std::numeric_limits<unsigned int>::max()));
	}

	uint64_t totalClusters64 = buf.f_blocks;
	uint64_t freeClusters64 = buf.f_bavail;

	if (lpSectorsPerCluster) {
		*lpSectorsPerCluster = sectorsPerCluster;
	}
	if (lpBytesPerSector) {
		*lpBytesPerSector = bytesPerSector;
	}
	if (lpNumberOfFreeClusters) {
		uint64_t clamped = std::min<uint64_t>(freeClusters64, std::numeric_limits<unsigned int>::max());
		*lpNumberOfFreeClusters = static_cast<DWORD>(clamped);
	}
	if (lpTotalNumberOfClusters) {
		uint64_t clamped = std::min<uint64_t>(totalClusters64, std::numeric_limits<unsigned int>::max());
		*lpTotalNumberOfClusters = static_cast<DWORD>(clamped);
	}

	DEBUG_LOG("\t-> host %s, spc %u, bps %u, free clusters %u, total clusters %u\n", resolvedPath.c_str(),
			  lpSectorsPerCluster ? *lpSectorsPerCluster : 0, lpBytesPerSector ? *lpBytesPerSector : 0,
			  lpNumberOfFreeClusters ? *lpNumberOfFreeClusters : 0,
			  lpTotalNumberOfClusters ? *lpTotalNumberOfClusters : 0);

	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC GetDiskFreeSpaceW(LPCWSTR lpRootPathName, LPDWORD lpSectorsPerCluster, LPDWORD lpBytesPerSector,
								LPDWORD lpNumberOfFreeClusters, LPDWORD lpTotalNumberOfClusters) {
	WIN_API_SEGMENT_GUARD();
	std::string rootPath = wideStringToString(lpRootPathName);
	return GetDiskFreeSpaceA(lpRootPathName ? rootPath.c_str() : nullptr, lpSectorsPerCluster, lpBytesPerSector,
							 lpNumberOfFreeClusters, lpTotalNumberOfClusters);
}

BOOL WIN_FUNC GetDiskFreeSpaceExA(LPCSTR lpDirectoryName, uint64_t *lpFreeBytesAvailableToCaller,
								  uint64_t *lpTotalNumberOfBytes, uint64_t *lpTotalNumberOfFreeBytes) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetDiskFreeSpaceExA(%s)\n", lpDirectoryName ? lpDirectoryName : "(null)");
	struct statvfs buf{};
	std::string resolvedPath;
	if (!resolveDiskFreeSpaceStat(lpDirectoryName, buf, resolvedPath)) {
		return FALSE;
	}

	uint64_t blockSize = buf.f_frsize ? buf.f_frsize : buf.f_bsize;
	if (blockSize == 0) {
		blockSize = 4096;
	}

	uint64_t freeToCaller = static_cast<uint64_t>(buf.f_bavail) * blockSize;
	uint64_t totalBytes = static_cast<uint64_t>(buf.f_blocks) * blockSize;
	uint64_t totalFree = static_cast<uint64_t>(buf.f_bfree) * blockSize;

	if (lpFreeBytesAvailableToCaller) {
		*lpFreeBytesAvailableToCaller = freeToCaller;
	}
	if (lpTotalNumberOfBytes) {
		*lpTotalNumberOfBytes = totalBytes;
	}
	if (lpTotalNumberOfFreeBytes) {
		*lpTotalNumberOfFreeBytes = totalFree;
	}

	DEBUG_LOG("\t-> host %s, free %llu, total %llu, total free %llu\n", resolvedPath.c_str(),
			  static_cast<unsigned long long>(freeToCaller), static_cast<unsigned long long>(totalBytes),
			  static_cast<unsigned long long>(totalFree));

	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC GetDiskFreeSpaceExW(LPCWSTR lpDirectoryName, uint64_t *lpFreeBytesAvailableToCaller,
								  uint64_t *lpTotalNumberOfBytes, uint64_t *lpTotalNumberOfFreeBytes) {
	WIN_API_SEGMENT_GUARD();
	DEBUG_LOG("GetDiskFreeSpaceExW -> ");
	std::string directoryName = wideStringToString(lpDirectoryName);
	return GetDiskFreeSpaceExA(lpDirectoryName ? directoryName.c_str() : nullptr, lpFreeBytesAvailableToCaller,
							   lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes);
}

} // namespace kernel32
