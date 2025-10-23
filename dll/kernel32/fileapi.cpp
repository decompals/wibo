#include "fileapi.h"

#include "access.h"
#include "async_io.h"
#include "common.h"
#include "context.h"
#include "errors.h"
#include "files.h"
#include "handles.h"
#include "internal.h"
#include "namedpipeapi.h"
#include "overlapped_util.h"
#include "strutil.h"
#include "timeutil.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/time.h>
#include <system_error>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace {

using random_shorts_engine =
	std::independent_bits_engine<std::default_random_engine, sizeof(unsigned short) * 8, unsigned short>;

constexpr uint64_t kWindowsTicksPerSecond = 10000000ULL;
constexpr uint64_t kSecondsBetween1601And1970 = 11644473600ULL;
const FILETIME kDefaultFindFileTime = {
	static_cast<DWORD>((kSecondsBetween1601And1970 * kWindowsTicksPerSecond) & 0xFFFFFFFFULL),
	static_cast<DWORD>((kSecondsBetween1601And1970 * kWindowsTicksPerSecond) >> 32)};

const FILETIME kDefaultFileInformationTime = {static_cast<DWORD>(UNIX_TIME_ZERO & 0xFFFFFFFFULL),
											  static_cast<DWORD>(UNIX_TIME_ZERO >> 32)};

using wibo::access::containsAny;

constexpr uint32_t kFileReadMask = FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES;
constexpr uint32_t kDirectoryReadMask = FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_EA | FILE_READ_ATTRIBUTES;
constexpr uint32_t kFileWriteMask = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES;
constexpr uint32_t kDirectoryWriteMask =
	FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES;

struct timespec accessTimespec(const struct stat &st) {
#if defined(__APPLE__)
	return st.st_atimespec;
#elif defined(__linux__)
	return st.st_atim;
#else
	struct timespec ts{};
	ts.tv_sec = st.st_atime;
	ts.tv_nsec = 0;
	return ts;
#endif
}

struct timespec modifyTimespec(const struct stat &st) {
#if defined(__APPLE__)
	return st.st_mtimespec;
#elif defined(__linux__)
	return st.st_mtim;
#else
	struct timespec ts{};
	ts.tv_sec = st.st_mtime;
	ts.tv_nsec = 0;
	return ts;
#endif
}

struct timespec changeTimespec(const struct stat &st) {
#if defined(__APPLE__)
	return st.st_ctimespec;
#elif defined(__linux__)
	return st.st_ctim;
#else
	struct timespec ts{};
	ts.tv_sec = st.st_ctime;
	ts.tv_nsec = 0;
	return ts;
#endif
}

struct FullPathInfo {
	std::string path;
	size_t filePartOffset = std::string::npos;
};

bool computeFullPath(const std::string &input, FullPathInfo &outInfo) {
	bool endsWithSeparator = false;
	if (!input.empty()) {
		char last = input.back();
		endsWithSeparator = (last == '\\' || last == '/');
	}

	std::filesystem::path hostPath = files::pathFromWindows(input.c_str());
	std::error_code ec;
	std::filesystem::path absPath = std::filesystem::absolute(hostPath, ec);
	if (ec) {
		wibo::lastError = wibo::winErrorFromErrno(ec.value());
		return false;
	}

	std::string windowsPath = files::pathToWindows(absPath);
	if (endsWithSeparator && !windowsPath.empty() && windowsPath.back() != '\\') {
		windowsPath.push_back('\\');
	}

	if (!windowsPath.empty() && windowsPath.back() != '\\') {
		size_t lastSlash = windowsPath.find_last_of('\\');
		if (lastSlash == std::string::npos) {
			outInfo.filePartOffset = 0;
		} else if (lastSlash + 1 < windowsPath.size()) {
			outInfo.filePartOffset = lastSlash + 1;
		}
	} else {
		outInfo.filePartOffset = std::string::npos;
	}

	outInfo.path = std::move(windowsPath);
	return true;
}

struct FindSearchEntry {
	std::string name;
	std::filesystem::path fullPath;
	bool isDirectory = false;
};

struct FindSearchHandle {
	bool singleResult = false;
	std::vector<FindSearchEntry> entries;
	size_t nextIndex = 0;
};

std::mutex g_findHandleMutex;
std::unordered_map<FindSearchHandle *, std::unique_ptr<FindSearchHandle>> g_findHandles;

HANDLE registerFindHandle(std::unique_ptr<FindSearchHandle> handle) {
	if (!handle) {
		return INVALID_HANDLE_VALUE;
	}
	FindSearchHandle *raw = handle.get();
	std::lock_guard lk(g_findHandleMutex);
	g_findHandles.emplace(raw, std::move(handle));
	return reinterpret_cast<HANDLE>(raw);
}

FindSearchHandle *lookupFindHandleLocked(HANDLE handle) {
	if (handle == nullptr) {
		return nullptr;
	}
	auto *raw = reinterpret_cast<FindSearchHandle *>(handle);
	auto it = g_findHandles.find(raw);
	if (it == g_findHandles.end()) {
		return nullptr;
	}
	return it->second.get();
}

std::unique_ptr<FindSearchHandle> detachFindHandle(HANDLE handle) {
	std::lock_guard lk(g_findHandleMutex);
	auto *raw = reinterpret_cast<FindSearchHandle *>(handle);
	auto it = g_findHandles.find(raw);
	if (it == g_findHandles.end()) {
		return nullptr;
	}
	auto owned = std::move(it->second);
	g_findHandles.erase(it);
	return owned;
}

bool containsWildcard(std::string_view value) { return value.find_first_of("*?") != std::string_view::npos; }

bool containsWildcardOutsideExtendedPrefix(std::string_view value) {
	if (value.rfind(R"(\\?\)", 0) == 0) {
		value.remove_prefix(4);
	}
	return containsWildcard(value);
}

inline char toLowerAscii(char ch) { return static_cast<char>(std::tolower(static_cast<unsigned char>(ch))); }

inline bool equalsIgnoreCase(char a, char b) { return toLowerAscii(a) == toLowerAscii(b); }

bool wildcardMatchInsensitive(std::string_view pattern, std::string_view text) {
	size_t p = 0;
	size_t t = 0;
	size_t star = std::string_view::npos;
	size_t match = 0;

	while (t < text.size()) {
		if (p < pattern.size()) {
			char pc = pattern[p];
			if (pc == '?') {
				++p;
				++t;
				continue;
			}
			if (pc == '*') {
				star = p++;
				match = t;
				continue;
			}
			if (equalsIgnoreCase(pc, text[t])) {
				++p;
				++t;
				continue;
			}
		}
		if (star != std::string_view::npos) {
			p = star + 1;
			t = ++match;
			continue;
		}
		return false;
	}

	while (p < pattern.size() && pattern[p] == '*') {
		++p;
	}
	return p == pattern.size();
}

void toFileTime(const struct timespec &ts, FILETIME &out) {
	int64_t seconds = static_cast<int64_t>(ts.tv_sec) + static_cast<int64_t>(kSecondsBetween1601And1970);
	if (seconds < 0) {
		seconds = 0;
	}
	uint64_t ticks = static_cast<uint64_t>(seconds) * kWindowsTicksPerSecond;
	ticks += static_cast<uint64_t>(ts.tv_nsec > 0 ? ts.tv_nsec / 100 : 0);
	out.dwLowDateTime = static_cast<DWORD>(ticks & 0xFFFFFFFFULL);
	out.dwHighDateTime = static_cast<DWORD>(ticks >> 32);
}

template <typename FindData> void resetFindDataStruct(FindData &data) { std::memset(&data, 0, sizeof(FindData)); }

void assignFileName(WIN32_FIND_DATAA &data, const std::string &name) {
	size_t count = std::min(name.size(), static_cast<size_t>(MAX_PATH - 1));
	std::memcpy(data.cFileName, name.data(), count);
	data.cFileName[count] = '\0';
}

void assignFileName(WIN32_FIND_DATAW &data, const std::string &name) {
	auto wide = stringToWideString(name.c_str(), name.size());
	size_t length = std::min<size_t>(wstrlen(wide.data()), MAX_PATH - 1);
	wstrncpy(data.cFileName, wide.data(), length);
	data.cFileName[length] = 0;
}

void clearAlternateName(WIN32_FIND_DATAA &data) { data.cAlternateFileName[0] = '\0'; }

void clearAlternateName(WIN32_FIND_DATAW &data) { data.cAlternateFileName[0] = 0; }

DWORD buildFileAttributes(const struct stat &st, bool isDirectory) {
	DWORD attributes = 0;
	mode_t mode = st.st_mode;
	if (S_ISDIR(mode) || isDirectory) {
		attributes |= FILE_ATTRIBUTE_DIRECTORY;
	}
	if (S_ISREG(mode) && !isDirectory) {
		attributes |= FILE_ATTRIBUTE_ARCHIVE;
	}
	if ((mode & S_IWUSR) == 0) {
		attributes |= FILE_ATTRIBUTE_READONLY;
	}
	if (attributes == 0) {
		attributes = FILE_ATTRIBUTE_NORMAL;
	}
	return attributes;
}

template <typename FindData> void populateFromStat(const FindSearchEntry &entry, const struct stat &st, FindData &out) {
	out.dwFileAttributes = buildFileAttributes(st, entry.isDirectory);
	uint64_t fileSize = (entry.isDirectory || !S_ISREG(st.st_mode)) ? 0ULL : static_cast<uint64_t>(st.st_size);
	out.nFileSizeHigh = static_cast<DWORD>(fileSize >> 32);
	out.nFileSizeLow = static_cast<DWORD>(fileSize & 0xFFFFFFFFULL);
	toFileTime(changeTimespec(st), out.ftCreationTime);
	toFileTime(accessTimespec(st), out.ftLastAccessTime);
	toFileTime(modifyTimespec(st), out.ftLastWriteTime);
}

template <typename FindData> void populateFindData(const FindSearchEntry &entry, FindData &out) {
	resetFindDataStruct(out);
	std::string nativePath = entry.fullPath.empty() ? std::string() : entry.fullPath.string();
	struct stat st{};
	if (!nativePath.empty() && stat(nativePath.c_str(), &st) == 0) {
		populateFromStat(entry, st, out);
	} else {
		out.dwFileAttributes = entry.isDirectory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
		out.ftCreationTime = kDefaultFindFileTime;
		out.ftLastAccessTime = kDefaultFindFileTime;
		out.ftLastWriteTime = kDefaultFindFileTime;
		out.nFileSizeHigh = 0;
		out.nFileSizeLow = 0;
	}
	assignFileName(out, entry.name);
	clearAlternateName(out);
}

std::filesystem::path parentOrSelf(const std::filesystem::path &path) {
	auto parent = path.parent_path();
	if (parent.empty()) {
		return path;
	}
	return parent;
}

std::filesystem::path resolvedPath(const std::filesystem::path &path) {
	std::error_code ec;
	auto canonical = std::filesystem::weakly_canonical(path, ec);
	if (!ec) {
		return canonical;
	}
	auto absolute = std::filesystem::absolute(path, ec);
	if (!ec) {
		return absolute;
	}
	return path;
}

std::string determineDisplayName(const std::filesystem::path &path, const std::string &filePart) {
	std::string name = path.filename().string();
	if (name.empty() || name == "." || name == "..") {
		std::error_code ec;
		auto absolute = std::filesystem::absolute(path, ec);
		if (!ec) {
			auto absoluteName = absolute.filename().string();
			if (!absoluteName.empty()) {
				name = absoluteName;
			}
		}
	}
	if (name.empty()) {
		name = filePart;
	}
	return name;
}

bool collectDirectoryMatches(const std::filesystem::path &directory, const std::string &pattern,
							 std::vector<FindSearchEntry> &outEntries) {
	auto addEntry = [&](const std::string &name, const std::filesystem::path &path, bool isDirectory) {
		FindSearchEntry entry;
		entry.name = name;
		entry.fullPath = resolvedPath(path);
		entry.isDirectory = isDirectory;
		outEntries.push_back(std::move(entry));
	};

	if (wildcardMatchInsensitive(pattern, ".")) {
		addEntry(".", directory, true);
	}
	if (wildcardMatchInsensitive(pattern, "..")) {
		addEntry("..", parentOrSelf(directory), true);
	}

	std::error_code iterEc;
	std::filesystem::directory_iterator end;
	for (std::filesystem::directory_iterator it(directory, iterEc); !iterEc && it != end; ++it) {
		std::string name = it->path().filename().string();
		if (!wildcardMatchInsensitive(pattern, name)) {
			continue;
		}
		std::error_code statusEc;
		bool isDir = it->is_directory(statusEc);
		if (statusEc) {
			isDir = false;
		}
		FindSearchEntry entry;
		entry.name = name;
		entry.fullPath = resolvedPath(it->path());
		entry.isDirectory = isDir;
		outEntries.push_back(std::move(entry));
	}
	if (iterEc) {
		wibo::lastError = wibo::winErrorFromErrno(iterEc.value());
		return false;
	}
	return true;
}

template <typename FindData> HANDLE findFirstFileCommon(const std::string &rawInput, FindData *lpFindFileData) {
	if (!lpFindFileData) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return INVALID_HANDLE_VALUE;
	}

	if (rawInput.empty()) {
		wibo::lastError = ERROR_PATH_NOT_FOUND;
		return INVALID_HANDLE_VALUE;
	}

	std::string input = rawInput;
	std::replace(input.begin(), input.end(), '/', '\\');

	if (input.empty()) {
		wibo::lastError = ERROR_PATH_NOT_FOUND;
		return INVALID_HANDLE_VALUE;
	}

	if (!input.empty() && input.back() == '\\') {
		wibo::lastError = ERROR_FILE_NOT_FOUND;
		return INVALID_HANDLE_VALUE;
	}

	std::string directoryPart;
	std::string filePart;
	size_t lastSlash = input.find_last_of('\\');
	if (lastSlash == std::string::npos) {
		directoryPart = ".";
		filePart = input;
	} else {
		directoryPart = input.substr(0, lastSlash);
		filePart = input.substr(lastSlash + 1);
		if (directoryPart.empty()) {
			directoryPart = "\\";
		} else if (lastSlash == 2 && input.size() >= 3 && input[1] == ':') {
			directoryPart = input.substr(0, lastSlash + 1);
		}
	}

	if (filePart.empty()) {
		wibo::lastError = ERROR_FILE_NOT_FOUND;
		return INVALID_HANDLE_VALUE;
	}

	if (containsWildcardOutsideExtendedPrefix(directoryPart)) {
		wibo::lastError = ERROR_INVALID_NAME;
		return INVALID_HANDLE_VALUE;
	}

	if (directoryPart.empty()) {
		directoryPart = ".";
	}

	std::filesystem::path hostDirectory = resolvedPath(files::pathFromWindows(directoryPart.c_str()));

	std::error_code dirStatusEc;
	auto dirStatus = std::filesystem::status(hostDirectory, dirStatusEc);
	if (dirStatusEc) {
		wibo::lastError = wibo::winErrorFromErrno(dirStatusEc.value());
		return INVALID_HANDLE_VALUE;
	}
	if (dirStatus.type() == std::filesystem::file_type::not_found) {
		wibo::lastError = ERROR_PATH_NOT_FOUND;
		return INVALID_HANDLE_VALUE;
	}
	if (dirStatus.type() != std::filesystem::file_type::directory) {
		wibo::lastError = ERROR_PATH_NOT_FOUND;
		return INVALID_HANDLE_VALUE;
	}

	bool hasWildcards = containsWildcard(filePart);

	if (!hasWildcards) {
		std::filesystem::path targetPath = resolvedPath(files::pathFromWindows(input.c_str()));

		std::error_code targetEc;
		auto targetStatus = std::filesystem::status(targetPath, targetEc);
		if (targetEc) {
			wibo::lastError = wibo::winErrorFromErrno(targetEc.value());
			return INVALID_HANDLE_VALUE;
		}
		if (targetStatus.type() == std::filesystem::file_type::not_found) {
			wibo::lastError = ERROR_FILE_NOT_FOUND;
			return INVALID_HANDLE_VALUE;
		}

		FindSearchEntry entry;
		entry.fullPath = targetPath;
		entry.isDirectory = targetStatus.type() == std::filesystem::file_type::directory;
		entry.name = determineDisplayName(targetPath, filePart);

		populateFindData(entry, *lpFindFileData);
		wibo::lastError = ERROR_SUCCESS;

		auto state = std::make_unique<FindSearchHandle>();
		state->singleResult = true;
		return registerFindHandle(std::move(state));
	}

	std::vector<FindSearchEntry> matches;
	if (!collectDirectoryMatches(hostDirectory, filePart, matches)) {
		return INVALID_HANDLE_VALUE;
	}
	if (matches.empty()) {
		wibo::lastError = ERROR_FILE_NOT_FOUND;
		return INVALID_HANDLE_VALUE;
	}

	populateFindData(matches[0], *lpFindFileData);
	wibo::lastError = ERROR_SUCCESS;

	auto state = std::make_unique<FindSearchHandle>();
	state->entries = std::move(matches);
	state->nextIndex = 1;
	return registerFindHandle(std::move(state));
}

std::optional<DWORD> stdHandleForConsoleDevice(const std::string &name, DWORD desiredAccess) {
	std::string lowered = stringToLower(name);
	if (lowered == "conin$") {
		return STD_INPUT_HANDLE;
	}
	if (lowered == "conout$") {
		return STD_OUTPUT_HANDLE;
	}
	if (lowered == "conerr$") {
		return STD_ERROR_HANDLE;
	}
	if (lowered == "con") {
		if ((desiredAccess & GENERIC_WRITE) != 0) {
			return STD_OUTPUT_HANDLE;
		}
		return STD_INPUT_HANDLE;
	}
	return std::nullopt;
}

bool tryOpenConsoleDevice(DWORD dwDesiredAccess, DWORD dwShareMode, DWORD dwCreationDisposition,
						  DWORD dwFlagsAndAttributes, HANDLE &outHandle, const std::string &originalName) {
	(void)dwShareMode;
	(void)dwCreationDisposition;
	(void)dwFlagsAndAttributes;
	auto stdHandleKind = stdHandleForConsoleDevice(originalName, dwDesiredAccess);
	if (!stdHandleKind) {
		return false;
	}
	HANDLE baseHandle = files::getStdHandle(*stdHandleKind);
	if (!wibo::handles().duplicateTo(baseHandle, wibo::handles(), outHandle, dwDesiredAccess, false, 0)) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		outHandle = INVALID_HANDLE_VALUE;
		return true;
	}
	return true;
}

} // namespace

namespace kernel32 {

DWORD WIN_FUNC GetFileAttributesA(LPCSTR lpFileName) {
	HOST_CONTEXT_GUARD();
	if (!lpFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return INVALID_FILE_ATTRIBUTES;
	}
	std::filesystem::path path = files::pathFromWindows(lpFileName);
	std::string pathStr = path.string();
	DEBUG_LOG("GetFileAttributesA(%s) -> %s\n", lpFileName, pathStr.c_str());

	if (endsWith(pathStr, "/license.dat")) {
		DEBUG_LOG("MWCC license override\n");
		return FILE_ATTRIBUTE_NORMAL;
	}

	std::error_code ec;
	auto status = std::filesystem::status(path, ec);
	if (ec) {
		wibo::lastError = wibo::winErrorFromErrno(ec.value());
		return INVALID_FILE_ATTRIBUTES;
	}

	switch (status.type()) {
	case std::filesystem::file_type::regular:
		DEBUG_LOG("File exists\n");
		return FILE_ATTRIBUTE_NORMAL;
	case std::filesystem::file_type::directory:
		return FILE_ATTRIBUTE_DIRECTORY;
	case std::filesystem::file_type::not_found:
	default:
		DEBUG_LOG("File does not exist\n");
		wibo::lastError = ERROR_FILE_NOT_FOUND;
		return INVALID_FILE_ATTRIBUTES;
	}
}

DWORD WIN_FUNC GetFileAttributesW(LPCWSTR lpFileName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetFileAttributesW -> ");
	if (!lpFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return INVALID_FILE_ATTRIBUTES;
	}
	std::string str = wideStringToString(lpFileName);
	return GetFileAttributesA(str.c_str());
}

UINT WIN_FUNC GetDriveTypeA(LPCSTR lpRootPathName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: GetDriveTypeA(%s)\n", lpRootPathName ? lpRootPathName : "(null)");
	(void)lpRootPathName;
	return DRIVE_FIXED;
}

UINT WIN_FUNC GetDriveTypeW(LPCWSTR lpRootPathName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: GetDriveTypeW(%p)\n", lpRootPathName);
	(void)lpRootPathName;
	return DRIVE_FIXED;
}

BOOL WIN_FUNC GetVolumeInformationA(LPCSTR lpRootPathName, LPSTR lpVolumeNameBuffer, DWORD nVolumeNameSize,
									LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength,
									LPDWORD lpFileSystemFlags, LPSTR lpFileSystemNameBuffer,
									DWORD nFileSystemNameSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: GetVolumeInformationA(%s)\n", lpRootPathName ? lpRootPathName : "(null)");
	if (lpVolumeNameBuffer && nVolumeNameSize > 0) {
		lpVolumeNameBuffer[0] = '\0';
	}
	if (lpVolumeSerialNumber) {
		*lpVolumeSerialNumber = 0x12345678;
	}
	if (lpMaximumComponentLength) {
		*lpMaximumComponentLength = 255;
	}
	if (lpFileSystemFlags) {
		*lpFileSystemFlags = 0;
	}
	if (lpFileSystemNameBuffer) {
		if (nFileSystemNameSize > 0) {
			const char *fsName = "NTFS";
			size_t copyLen = std::min<size_t>(std::strlen(fsName), nFileSystemNameSize - 1);
			std::memcpy(lpFileSystemNameBuffer, fsName, copyLen);
			lpFileSystemNameBuffer[copyLen] = '\0';
		}
	}
	return TRUE;
}

BOOL WIN_FUNC GetVolumeInformationW(LPCWSTR lpRootPathName, LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize,
									LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength,
									LPDWORD lpFileSystemFlags, LPWSTR lpFileSystemNameBuffer,
									DWORD nFileSystemNameSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: GetVolumeInformationW(%p)\n", lpRootPathName);
	if (lpVolumeNameBuffer && nVolumeNameSize > 0) {
		lpVolumeNameBuffer[0] = 0;
	}
	if (lpVolumeSerialNumber) {
		*lpVolumeSerialNumber = 0x12345678;
	}
	if (lpMaximumComponentLength) {
		*lpMaximumComponentLength = 255;
	}
	if (lpFileSystemFlags) {
		*lpFileSystemFlags = 0;
	}
	if (lpFileSystemNameBuffer) {
		if (nFileSystemNameSize > 0) {
			std::vector<uint16_t> fsWide = stringToWideString("NTFS");
			size_t copyLen = std::min<size_t>(fsWide.size() > 0 ? fsWide.size() - 1 : 0, nFileSystemNameSize - 1);
			for (size_t i = 0; i < copyLen; ++i) {
				lpFileSystemNameBuffer[i] = static_cast<uint16_t>(fsWide[i]);
			}
			lpFileSystemNameBuffer[copyLen] = 0;
		}
	}
	return TRUE;
}

LONG WIN_FUNC CompareFileTime(const FILETIME *lpFileTime1, const FILETIME *lpFileTime2) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CompareFileTime(%p, %p)\n", lpFileTime1, lpFileTime2);
	auto toInt64 = [](const FILETIME *ft) -> int64_t {
		if (!ft) {
			return 0;
		}
		uint64_t combined = (static_cast<uint64_t>(ft->dwHighDateTime) << 32) | ft->dwLowDateTime;
		return static_cast<int64_t>(combined);
	};
	int64_t value1 = toInt64(lpFileTime1);
	int64_t value2 = toInt64(lpFileTime2);
	if (value1 < value2) {
		return -1;
	}
	if (value1 > value2) {
		return 1;
	}
	return 0;
}

BOOL WIN_FUNC WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten,
						LPOVERLAPPED lpOverlapped) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("WriteFile(%p, %p, %u, %p, %p)\n", hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten,
			  lpOverlapped);

	HandleMeta meta{};
	auto file = wibo::handles().getAs<FileObject>(hFile, &meta);
	if (!file || !file->valid()) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
#ifdef CHECK_ACCESS
	if ((meta.grantedAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)) == 0) {
		wibo::lastError = ERROR_ACCESS_DENIED;
		DEBUG_LOG("!!! DENIED: 0x%x\n", meta.grantedAccess);
		return FALSE;
	}
#endif

	if (lpOverlapped == nullptr && lpNumberOfBytesWritten == nullptr) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	std::optional<off_t> offset;
	bool updateFilePointer = true;
	if (lpOverlapped != nullptr) {
		offset = static_cast<off_t>((static_cast<uint64_t>(lpOverlapped->Offset)) |
									(static_cast<uint64_t>(lpOverlapped->OffsetHigh) << 32));
		lpOverlapped->Internal = STATUS_PENDING;
		lpOverlapped->InternalHigh = 0;
		updateFilePointer = !file->overlapped;
		detail::resetOverlappedEvent(lpOverlapped);
		if (file->overlapped) {
			if (nNumberOfBytesToWrite == 0) {
				lpOverlapped->Internal = STATUS_SUCCESS;
				lpOverlapped->InternalHigh = 0;
				detail::signalOverlappedEvent(lpOverlapped);
				if (lpNumberOfBytesWritten) {
					*lpNumberOfBytesWritten = 0;
				}
				return TRUE;
			}
			if (wibo::asyncIO().queueWrite(file.clone(), lpOverlapped, lpBuffer, nNumberOfBytesToWrite, offset,
										   file->isPipe)) {
				if (lpNumberOfBytesWritten) {
					*lpNumberOfBytesWritten = 0;
				}
				wibo::lastError = ERROR_IO_PENDING;
				return FALSE;
			}
		}
	}

	auto io = files::write(file.get(), lpBuffer, nNumberOfBytesToWrite, offset, updateFilePointer);
	DWORD completionStatus = STATUS_SUCCESS;
	if (io.unixError != 0) {
		completionStatus = wibo::statusFromErrno(io.unixError);
		wibo::lastError = wibo::winErrorFromErrno(io.unixError);
	} else if (io.reachedEnd && io.bytesTransferred == 0) {
		completionStatus = STATUS_END_OF_FILE;
	}

	if (lpNumberOfBytesWritten && (!file->overlapped || lpOverlapped == nullptr)) {
		*lpNumberOfBytesWritten = static_cast<DWORD>(io.bytesTransferred);
	}

	if (lpOverlapped != nullptr) {
		lpOverlapped->Internal = completionStatus;
		lpOverlapped->InternalHigh = io.bytesTransferred;
		detail::signalOverlappedEvent(lpOverlapped);
	}

	return io.unixError == 0;
}

BOOL WIN_FUNC FlushFileBuffers(HANDLE hFile) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FlushFileBuffers(%p)\n", hFile);
	auto file = wibo::handles().getAs<FileObject>(hFile);
	if (!file || !file->valid()) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	if (fsync(file->fd) != 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
	return TRUE;
}

BOOL WIN_FUNC ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead,
					   LPOVERLAPPED lpOverlapped) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("ReadFile(%p, %p, %u, %p, %p)\n", hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead,
			  lpOverlapped);

	HandleMeta meta{};
	auto file = wibo::handles().getAs<FileObject>(hFile, &meta);
	if (!file || !file->valid()) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
#ifdef CHECK_ACCESS
	if ((meta.grantedAccess & FILE_READ_DATA) == 0) {
		wibo::lastError = ERROR_ACCESS_DENIED;
		DEBUG_LOG("!!! DENIED: 0x%x\n", meta.grantedAccess);
		return FALSE;
	}
#endif

	if (lpOverlapped == nullptr && lpNumberOfBytesRead == nullptr) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	if (lpNumberOfBytesRead && (!file->overlapped || lpOverlapped == nullptr)) {
		*lpNumberOfBytesRead = 0;
	}

	std::optional<off_t> offset;
	bool updateFilePointer = true;
	if (lpOverlapped != nullptr) {
		offset = static_cast<off_t>((static_cast<uint64_t>(lpOverlapped->Offset)) |
									(static_cast<uint64_t>(lpOverlapped->OffsetHigh) << 32));
		lpOverlapped->Internal = STATUS_PENDING;
		lpOverlapped->InternalHigh = 0;
		updateFilePointer = !file->overlapped;
		detail::resetOverlappedEvent(lpOverlapped);
		if (file->overlapped) {
			if (nNumberOfBytesToRead == 0) {
				lpOverlapped->Internal = STATUS_SUCCESS;
				lpOverlapped->InternalHigh = 0;
				detail::signalOverlappedEvent(lpOverlapped);
				if (lpNumberOfBytesRead) {
					*lpNumberOfBytesRead = 0;
				}
				return TRUE;
			}
			if (wibo::asyncIO().queueRead(file.clone(), lpOverlapped, lpBuffer, nNumberOfBytesToRead, offset,
										  file->isPipe)) {
				if (lpNumberOfBytesRead) {
					*lpNumberOfBytesRead = 0;
				}
				wibo::lastError = ERROR_IO_PENDING;
				return FALSE;
			}
		}
	}

	auto io = files::read(file.get(), lpBuffer, nNumberOfBytesToRead, offset, updateFilePointer);
	DWORD completionStatus = STATUS_SUCCESS;
	if (io.unixError != 0) {
		completionStatus = wibo::statusFromErrno(io.unixError);
		wibo::lastError = wibo::winErrorFromErrno(io.unixError);
	} else if (io.reachedEnd && io.bytesTransferred == 0) {
		if (file->isPipe) {
			completionStatus = STATUS_PIPE_BROKEN;
			wibo::lastError = ERROR_BROKEN_PIPE;
			if (lpOverlapped != nullptr) {
				lpOverlapped->Internal = completionStatus;
				lpOverlapped->InternalHigh = 0;
				detail::signalOverlappedEvent(lpOverlapped);
			}
			DEBUG_LOG("-> ERROR_BROKEN_PIPE\n");
			return FALSE;
		}
		completionStatus = STATUS_END_OF_FILE;
	}

	if (lpNumberOfBytesRead && (!file->overlapped || lpOverlapped == nullptr)) {
		*lpNumberOfBytesRead = static_cast<DWORD>(io.bytesTransferred);
	}

	if (lpOverlapped != nullptr) {
		lpOverlapped->Internal = completionStatus;
		lpOverlapped->InternalHigh = io.bytesTransferred;
		detail::signalOverlappedEvent(lpOverlapped);
	}

	DEBUG_LOG("-> %u bytes read, error %d\n", io.bytesTransferred, io.unixError == 0 ? 0 : wibo::lastError);
	return io.unixError == 0;
}

HANDLE WIN_FUNC CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
							LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
							DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
	HOST_CONTEXT_GUARD();
	(void)hTemplateFile;
	if (!lpFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return INVALID_HANDLE_VALUE;
	}

	HANDLE consoleHandle = INVALID_HANDLE_VALUE;
	if (tryOpenConsoleDevice(dwDesiredAccess, dwShareMode, dwCreationDisposition, dwFlagsAndAttributes, consoleHandle,
							 std::string(lpFileName))) {
		DEBUG_LOG("CreateFileA(console=%s, desiredAccess=0x%x, shareMode=%u, flags=0x%x) -> %p\n", lpFileName,
				  dwDesiredAccess, dwShareMode, dwFlagsAndAttributes, consoleHandle);
		return consoleHandle;
	}

	HANDLE pipeHandle = INVALID_HANDLE_VALUE;
	if (kernel32::tryCreateFileNamedPipeA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
										  dwCreationDisposition, dwFlagsAndAttributes, pipeHandle)) {
		DEBUG_LOG("CreateFileA(pipe=%s) -> %p (err=%u)\n", lpFileName, pipeHandle, wibo::lastError);
		return pipeHandle;
	}

	std::filesystem::path hostPath = files::pathFromWindows(lpFileName);
	std::string hostPathStr = hostPath.string();
	DEBUG_LOG("CreateFileA(filename=%s (%s), desiredAccess=0x%x, shareMode=%u, securityAttributes=%p, "
			  "creationDisposition=%u, flagsAndAttributes=%u)\n",
			  lpFileName, hostPathStr.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes,
			  dwCreationDisposition, dwFlagsAndAttributes);

	constexpr DWORD kAttributeMask = 0x0000FFFFu;
	DWORD fileAttributes = dwFlagsAndAttributes & kAttributeMask;
	bool backupSemantics = (dwFlagsAndAttributes & FILE_FLAG_BACKUP_SEMANTICS) != 0;
	bool deleteOnClose = (dwFlagsAndAttributes & FILE_FLAG_DELETE_ON_CLOSE) != 0;
	bool overlapped = (dwFlagsAndAttributes & FILE_FLAG_OVERLAPPED) != 0;

	std::error_code statusEc;
	std::filesystem::file_status status = std::filesystem::status(hostPath, statusEc);
	bool pathExists = !statusEc && status.type() != std::filesystem::file_type::not_found;
	bool isDirectory = pathExists && status.type() == std::filesystem::file_type::directory;

	if ((fileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 && !isDirectory) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		DEBUG_LOG("-> ERROR_INVALID_PARAMETER (ENOTDIR)\n");
		return INVALID_HANDLE_VALUE;
	}
	if (isDirectory && (!backupSemantics || deleteOnClose /* not currently implemented for dir */)) {
		wibo::lastError = ERROR_ACCESS_DENIED;
		DEBUG_LOG("-> ERROR_ACCESS_DENIED (EISDIR)\n");
		return INVALID_HANDLE_VALUE;
	}

	// TODO: verify share mode against existing opens

	bool allowCreate = false;
	bool truncateExisting = false;
	bool existedBefore = pathExists;

	switch (dwCreationDisposition) {
	case CREATE_NEW:
		allowCreate = true;
		if (pathExists) {
			wibo::lastError = ERROR_FILE_EXISTS;
			DEBUG_LOG("-> ERROR_FILE_EXISTS (EEXIST)");
			return INVALID_HANDLE_VALUE;
		}
		break;
	case CREATE_ALWAYS:
		allowCreate = true;
		if (isDirectory) {
			wibo::lastError = ERROR_ACCESS_DENIED;
			DEBUG_LOG("-> ERROR_ACCESS_DENIED (EISDIR)");
			return INVALID_HANDLE_VALUE;
		}
		truncateExisting = pathExists;
		break;
	case OPEN_ALWAYS:
		if (!pathExists) {
			allowCreate = true;
		} else if (isDirectory) {
			wibo::lastError = ERROR_ACCESS_DENIED;
			DEBUG_LOG("-> ERROR_ACCESS_DENIED (EISDIR)");
			return INVALID_HANDLE_VALUE;
		}
		break;
	case OPEN_EXISTING:
		if (!pathExists) {
			wibo::lastError = ERROR_FILE_NOT_FOUND;
			DEBUG_LOG("-> ERROR_FILE_NOT_FOUND (ENOENT)");
			return INVALID_HANDLE_VALUE;
		}
		break;
	case TRUNCATE_EXISTING:
		if (!pathExists) {
			wibo::lastError = ERROR_FILE_NOT_FOUND;
			DEBUG_LOG("-> ERROR_FILE_NOT_FOUND (ENOENT)");
			return INVALID_HANDLE_VALUE;
		}
		if (isDirectory) {
			wibo::lastError = ERROR_ACCESS_DENIED;
			DEBUG_LOG("-> ERROR_ACCESS_DENIED (EISDIR)");
			return INVALID_HANDLE_VALUE;
		}
		truncateExisting = true;
		break;
	default:
		assert(false);
	}

	const auto &genericMapping =
		isDirectory ? wibo::access::kDirectoryGenericMapping : wibo::access::kFileGenericMapping;
	uint32_t supportedMask = isDirectory ? (FILE_ALL_ACCESS | wibo::access::kDirectorySpecificRightsMask)
										 : (FILE_ALL_ACCESS | wibo::access::kFileSpecificRightsMask);
	uint32_t defaultMask = FILE_READ_ATTRIBUTES;
	auto normalized =
		wibo::access::normalizeDesiredAccess(dwDesiredAccess, genericMapping, supportedMask, SYNCHRONIZE, defaultMask);
	if (normalized.deniedMask != 0) {
		wibo::lastError = ERROR_ACCESS_DENIED;
		DEBUG_LOG("-> ERROR_ACCESS_DENIED: denied mask 0x%x\n", normalized.deniedMask);
		return INVALID_HANDLE_VALUE;
	}

	bool wantsRead = containsAny(normalized.grantedMask, isDirectory ? kDirectoryReadMask : kFileReadMask) ||
					 containsAny(normalized.grantedMask, FILE_EXECUTE);
	bool wantsWrite = containsAny(normalized.grantedMask, isDirectory ? kDirectoryWriteMask : kFileWriteMask);
	bool appendRequested = !isDirectory && containsAny(normalized.grantedMask, FILE_APPEND_DATA);
	bool appendOnly = appendRequested && !containsAny(normalized.grantedMask, FILE_WRITE_DATA);
#ifdef CHECK_ACCESS
	if (allowCreate && !containsAny(normalized.grantedMask, FILE_WRITE_DATA | FILE_APPEND_DATA)) {
		wibo::lastError = ERROR_ACCESS_DENIED;
		DEBUG_LOG("-> ERROR_ACCESS_DENIED: FILE_WRITE_DATA | FILE_APPEND_DATA required for creation");
		return INVALID_HANDLE_VALUE;
	}
	if (truncateExisting && !containsAny(normalized.grantedMask, FILE_WRITE_DATA)) {
		wibo::lastError = ERROR_ACCESS_DENIED;
		DEBUG_LOG("-> ERROR_ACCESS_DENIED: FILE_WRITE_DATA required for truncation");
		return INVALID_HANDLE_VALUE;
	}
	if (deleteOnClose && !containsAny(normalized.grantedMask, DELETE)) {
		wibo::lastError = ERROR_ACCESS_DENIED;
		DEBUG_LOG("-> ERROR_ACCESS_DENIED: DELETE required for delete-on-close");
		return INVALID_HANDLE_VALUE;
	}
#else
	(void)allowCreate;
#endif

	uint32_t shareMask = dwShareMode & (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);

	int openFlags = O_CLOEXEC;
	mode_t createMode = 0666;
	bool requestCreate = false;
	if (dwCreationDisposition == CREATE_NEW || dwCreationDisposition == CREATE_ALWAYS ||
		(dwCreationDisposition == OPEN_ALWAYS && !pathExists)) {
		requestCreate = true;
		openFlags |= O_CREAT;
	}
	if (dwCreationDisposition == CREATE_NEW) {
		openFlags |= O_EXCL;
	}
	if (truncateExisting && !isDirectory) {
		openFlags |= O_TRUNC;
	}

	if (isDirectory) {
		openFlags |= O_RDONLY | O_DIRECTORY;
		wantsRead = true;
	} else {
		bool needWrite = wantsWrite || truncateExisting || requestCreate;
		bool needRead = wantsRead || !needWrite;
		if (needWrite && needRead) {
			openFlags |= O_RDWR;
		} else if (needWrite) {
			openFlags |= O_WRONLY;
		} else {
			openFlags |= O_RDONLY;
		}
		if (appendOnly) {
			openFlags |= O_APPEND;
		}
	}

	int fd = open(hostPathStr.c_str(), openFlags, createMode);
	if (fd < 0) {
		setLastErrorFromErrno();
		DEBUG_LOG("-> errno: %d\n", errno);
		return INVALID_HANDLE_VALUE;
	}

	struct stat st{};
	if (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
		isDirectory = true;
	}

	bool createdNew = !existedBefore && requestCreate;
	std::filesystem::path canonicalPath = files::canonicalPath(hostPath);

	Pin<FsObject> fsObject;
	if (isDirectory) {
		fsObject = make_pin<DirectoryObject>(fd);
	} else {
		auto fileObj = make_pin<FileObject>(fd);
		fileObj->overlapped = overlapped;
		fileObj->appendOnly = appendOnly;
		fsObject = std::move(fileObj);
	}
	fsObject->canonicalPath = std::move(canonicalPath);
	fsObject->shareAccess = shareMask;
	fsObject->deletePending = deleteOnClose;

	uint32_t handleFlags = 0;
	if (lpSecurityAttributes && lpSecurityAttributes->bInheritHandle) {
		handleFlags |= HANDLE_FLAG_INHERIT;
	}
	HANDLE handle = wibo::handles().alloc(std::move(fsObject), normalized.grantedMask, handleFlags);

	if ((dwCreationDisposition == OPEN_ALWAYS && existedBefore) ||
		(dwCreationDisposition == CREATE_ALWAYS && existedBefore)) {
		wibo::lastError = ERROR_ALREADY_EXISTS;
	}

	DEBUG_LOG("-> %p (createdNew=%d, truncate=%d)\n", handle, createdNew ? 1 : 0, truncateExisting ? 1 : 0);
	return handle;
}

HANDLE WIN_FUNC CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
							LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
							DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CreateFileW -> ");
	if (!lpFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return INVALID_HANDLE_VALUE;
	}
	std::string lpFileNameA = wideStringToString(lpFileName);
	return CreateFileA(lpFileNameA.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition,
					   dwFlagsAndAttributes, hTemplateFile);
}

BOOL WIN_FUNC DeleteFileA(LPCSTR lpFileName) {
	HOST_CONTEXT_GUARD();
	if (!lpFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		DEBUG_LOG("DeleteFileA(NULL) -> ERROR_INVALID_PARAMETER\n");
		return FALSE;
	}
	std::string path = files::pathFromWindows(lpFileName);
	DEBUG_LOG("DeleteFileA(%s) -> %s\n", lpFileName, path.c_str());
	if (unlink(path.c_str()) != 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
	return TRUE;
}

BOOL WIN_FUNC DeleteFileW(LPCWSTR lpFileName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("DeleteFileW -> ");
	if (!lpFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	std::string name = wideStringToString(lpFileName);
	return DeleteFileA(name.c_str());
}

BOOL WIN_FUNC MoveFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("MoveFileA(%s, %s)\n", lpExistingFileName ? lpExistingFileName : "(null)",
			  lpNewFileName ? lpNewFileName : "(null)");
	if (!lpExistingFileName || !lpNewFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	auto fromPath = files::pathFromWindows(lpExistingFileName);
	auto toPath = files::pathFromWindows(lpNewFileName);
	std::error_code ec;
	if (std::filesystem::exists(toPath, ec)) {
		wibo::lastError = ERROR_ALREADY_EXISTS;
		return FALSE;
	}
	if (ec) {
		wibo::lastError = wibo::winErrorFromErrno(ec.value());
		return FALSE;
	}
	std::filesystem::rename(fromPath, toPath, ec);
	if (ec) {
		wibo::lastError = wibo::winErrorFromErrno(ec.value());
		return FALSE;
	}
	return TRUE;
}

BOOL WIN_FUNC MoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("MoveFileW -> ");
	if (!lpExistingFileName || !lpNewFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	std::string from = wideStringToString(lpExistingFileName);
	std::string to = wideStringToString(lpNewFileName);
	return MoveFileA(from.c_str(), to.c_str());
}

DWORD WIN_FUNC SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetFilePointer(%p, %ld, %p, %u)\n", hFile, static_cast<long>(lDistanceToMove), lpDistanceToMoveHigh,
			  dwMoveMethod);
	if (hFile == nullptr) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return INVALID_SET_FILE_POINTER;
	}
	HandleMeta meta{};
	auto file = wibo::handles().getAs<FileObject>(hFile, &meta);
	if (!file) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return INVALID_SET_FILE_POINTER;
	}
	// TODO access check
	std::lock_guard lk(file->m);
	off_t position = 0;
	off_t offset = static_cast<off_t>(lDistanceToMove);
	if (dwMoveMethod == FILE_BEGIN) {
		position = offset;
	} else if (dwMoveMethod == FILE_CURRENT) {
		position = file->filePos + offset;
	} else if (dwMoveMethod == FILE_END) {
		position = lseek(file->fd, offset, SEEK_END);
	}
	if (position < 0) {
		if (errno == EINVAL) {
			wibo::lastError = ERROR_NEGATIVE_SEEK;
		} else {
			wibo::lastError = ERROR_INVALID_PARAMETER;
		}
		return INVALID_SET_FILE_POINTER;
	}
	file->filePos = position;
	if (lpDistanceToMoveHigh) {
		*lpDistanceToMoveHigh = static_cast<LONG>(static_cast<uint64_t>(position) >> 32);
	}
	return static_cast<DWORD>(static_cast<uint64_t>(position) & 0xFFFFFFFFu);
}

BOOL WIN_FUNC SetFilePointerEx(HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpNewFilePointer,
							   DWORD dwMoveMethod) {
	HOST_CONTEXT_GUARD();
	if (hFile == nullptr) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	HandleMeta meta{};
	auto file = wibo::handles().getAs<FileObject>(hFile, &meta);
	if (!file) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	// TODO access check
	std::lock_guard lk(file->m);
	off_t position = 0;
	off_t offset = static_cast<off_t>(liDistanceToMove);
	if (dwMoveMethod == FILE_BEGIN) {
		position = offset;
	} else if (dwMoveMethod == FILE_CURRENT) {
		position = file->filePos + offset;
	} else if (dwMoveMethod == FILE_END) {
		position = lseek(file->fd, offset, SEEK_END);
	}
	if (position < 0) {
		if (errno == EINVAL) {
			wibo::lastError = ERROR_NEGATIVE_SEEK;
		} else {
			wibo::lastError = ERROR_INVALID_PARAMETER;
		}
		return INVALID_SET_FILE_POINTER;
	}
	file->filePos = position;
	if (position < 0) {
		if (errno == EINVAL) {
			wibo::lastError = ERROR_NEGATIVE_SEEK;
		} else {
			wibo::lastError = ERROR_INVALID_PARAMETER;
		}
		return FALSE;
	}
	if (lpNewFilePointer) {
		*lpNewFilePointer = static_cast<LARGE_INTEGER>(position);
	}
	return TRUE;
}

BOOL WIN_FUNC SetEndOfFile(HANDLE hFile) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetEndOfFile(%p)\n", hFile);
	HandleMeta meta{};
	auto file = wibo::handles().getAs<FileObject>(hFile, &meta);
	if (!file) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	// TODO access check
	std::lock_guard lk(file->m);
	if (file->filePos < 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
	if (ftruncate(file->fd, file->filePos) != 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
	return TRUE;
}

BOOL WIN_FUNC CreateDirectoryA(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes) {
	HOST_CONTEXT_GUARD();
	(void)lpSecurityAttributes;
	if (!lpPathName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	std::string path = files::pathFromWindows(lpPathName);
	DEBUG_LOG("CreateDirectoryA(%s, %p)\n", path.c_str(), lpSecurityAttributes);
	if (mkdir(path.c_str(), 0755) != 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
	return TRUE;
}

BOOL WIN_FUNC RemoveDirectoryA(LPCSTR lpPathName) {
	HOST_CONTEXT_GUARD();
	if (!lpPathName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	std::string path = files::pathFromWindows(lpPathName);
	DEBUG_LOG("RemoveDirectoryA(%s)\n", path.c_str());
	if (rmdir(path.c_str()) != 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
	return TRUE;
}

BOOL WIN_FUNC SetFileAttributesA(LPCSTR lpFileName, DWORD dwFileAttributes) {
	HOST_CONTEXT_GUARD();
	(void)dwFileAttributes;
	if (!lpFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	DEBUG_LOG("STUB: SetFileAttributesA(%s, %u)\n", lpFileName, dwFileAttributes);
	return TRUE;
}

DWORD WIN_FUNC GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetFileSize(%p, %p) ", hFile, lpFileSizeHigh);
	// TODO access check
	auto file = wibo::handles().getAs<FileObject>(hFile);
	if (!file || !file->valid()) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		DEBUG_LOG("-> INVALID_FILE_SIZE (ERROR_INVALID_HANDLE)\n");
		return INVALID_FILE_SIZE;
	}
	const auto size = lseek(file->fd, 0, SEEK_END);
	if (size < 0) {
		if (lpFileSizeHigh) {
			*lpFileSizeHigh = 0;
		}
		DEBUG_LOG("-> INVALID_FILE_SIZE\n");
		return INVALID_FILE_SIZE;
	}
	DEBUG_LOG("-> %lld\n", size);
	uint64_t uSize = static_cast<uint64_t>(size);
	if (lpFileSizeHigh) {
		*lpFileSizeHigh = static_cast<DWORD>(uSize >> 32);
	}
	return static_cast<DWORD>(uSize & 0xFFFFFFFFu);
}

BOOL WIN_FUNC GetFileTime(HANDLE hFile, LPFILETIME lpCreationTime, LPFILETIME lpLastAccessTime,
						  LPFILETIME lpLastWriteTime) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetFileTime(%p, %p, %p, %p)\n", hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime);
	HandleMeta meta{};
	auto file = wibo::handles().getAs<FileObject>(hFile, &meta);
	if (!file || !file->valid()) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
#ifdef CHECK_ACCESS
	if ((meta.grantedAccess & FILE_READ_ATTRIBUTES) == 0) {
		wibo::lastError = ERROR_ACCESS_DENIED;
		return FALSE;
	}
#endif

	struct stat st{};
	if (fstat(file->fd, &st) != 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
	auto assignFileTime = [](LPFILETIME target, const struct timespec &spec) -> bool {
		if (!target) {
			return true;
		}
		FILETIME result{};
		uint32_t hundreds = static_cast<uint32_t>(spec.tv_nsec / 100L);
		if (!unixPartsToFileTime(static_cast<int64_t>(spec.tv_sec), hundreds, result)) {
			return false;
		}
		*target = result;
		return true;
	};
	if (!assignFileTime(lpCreationTime, changeTimespec(st)) || !assignFileTime(lpLastAccessTime, accessTimespec(st)) ||
		!assignFileTime(lpLastWriteTime, modifyTimespec(st))) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	return TRUE;
}

BOOL WIN_FUNC SetFileTime(HANDLE hFile, const FILETIME *lpCreationTime, const FILETIME *lpLastAccessTime,
						  const FILETIME *lpLastWriteTime) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetFileTime(%p, %p, %p, %p)\n", hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime);
	HandleMeta meta{};
	auto file = wibo::handles().getAs<FileObject>(hFile, &meta);
	if (!file || !file->valid()) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
#ifdef CHECK_ACCESS
	if ((meta.grantedAccess & FILE_WRITE_ATTRIBUTES) == 0) {
		wibo::lastError = ERROR_ACCESS_DENIED;
		return FALSE;
	}
#endif

	bool changeAccess = !shouldIgnoreFileTimeParam(lpLastAccessTime);
	bool changeWrite = !shouldIgnoreFileTimeParam(lpLastWriteTime);
	if (!changeAccess && !changeWrite) {
		return TRUE;
	}
	struct stat st{};
	if (fstat(file->fd, &st) != 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
	struct timespec accessSpec = accessTimespec(st);
	struct timespec writeSpec = modifyTimespec(st);
	if (changeAccess) {
		int64_t seconds = 0;
		uint32_t hundreds = 0;
		if (!fileTimeToUnixParts(*lpLastAccessTime, seconds, hundreds) ||
			!unixPartsToTimespec(seconds, hundreds, accessSpec)) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
	}
	if (changeWrite) {
		int64_t seconds = 0;
		uint32_t hundreds = 0;
		if (!fileTimeToUnixParts(*lpLastWriteTime, seconds, hundreds) ||
			!unixPartsToTimespec(seconds, hundreds, writeSpec)) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return FALSE;
		}
	}
#if defined(__APPLE__) || defined(__FreeBSD__)
	struct timeval tv[2];
	tv[0].tv_sec = accessSpec.tv_sec;
	tv[0].tv_usec = accessSpec.tv_nsec / 1000L;
	tv[1].tv_sec = writeSpec.tv_sec;
	tv[1].tv_usec = writeSpec.tv_nsec / 1000L;
	if (futimes(file->fd, tv) != 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
#else
	struct timespec times[2] = {accessSpec, writeSpec};
	if (futimens(file->fd, times) != 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
#endif
	if (!shouldIgnoreFileTimeParam(lpCreationTime) && lpCreationTime) {
		DEBUG_LOG("SetFileTime: creation time not supported\n");
	}
	return TRUE;
}

BOOL WIN_FUNC GetFileInformationByHandle(HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetFileInformationByHandle(%p, %p)\n", hFile, lpFileInformation);
	if (!lpFileInformation) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	HandleMeta meta{};
	auto file = wibo::handles().getAs<FileObject>(hFile, &meta);
	if (!file || !file->valid()) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	// TODO access check
	struct stat st{};
	if (fstat(file->fd, &st) != 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
	lpFileInformation->dwFileAttributes = 0;
	if (S_ISDIR(st.st_mode)) {
		lpFileInformation->dwFileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
	}
	if (S_ISREG(st.st_mode)) {
		lpFileInformation->dwFileAttributes |= FILE_ATTRIBUTE_NORMAL;
	}
	lpFileInformation->ftCreationTime = kDefaultFileInformationTime;
	lpFileInformation->ftLastAccessTime = kDefaultFileInformationTime;
	lpFileInformation->ftLastWriteTime = kDefaultFileInformationTime;
	lpFileInformation->dwVolumeSerialNumber = 0;
	lpFileInformation->nFileSizeHigh = static_cast<DWORD>(static_cast<uint64_t>(st.st_size) >> 32);
	lpFileInformation->nFileSizeLow = static_cast<DWORD>(st.st_size & 0xFFFFFFFFULL);
	lpFileInformation->nNumberOfLinks = 0;
	lpFileInformation->nFileIndexHigh = 0;
	lpFileInformation->nFileIndexLow = 0;
	return TRUE;
}

DWORD WIN_FUNC GetFileType(HANDLE hFile) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetFileType(%p) ", hFile);
	auto file = wibo::handles().getAs<FileObject>(hFile);
	if (!file || !file->valid()) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		DEBUG_LOG("-> ERROR_INVALID_HANDLE\n");
		return FILE_TYPE_UNKNOWN;
	}
	struct stat st{};
	if (fstat(file->fd, &st) != 0) {
		setLastErrorFromErrno();
		DEBUG_LOG("-> fstat error\n");
		return FILE_TYPE_UNKNOWN;
	}
	DWORD type = FILE_TYPE_UNKNOWN;
	if (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode) || S_ISBLK(st.st_mode)) {
		type = FILE_TYPE_DISK;
	}
	if (S_ISCHR(st.st_mode)) {
		type = FILE_TYPE_CHAR;
	}
	if (S_ISSOCK(st.st_mode) || S_ISFIFO(st.st_mode)) {
		type = FILE_TYPE_PIPE;
	}
	DEBUG_LOG("-> %u\n", type);
	return type;
}

DWORD WIN_FUNC GetFullPathNameA(LPCSTR lpFileName, DWORD nBufferLength, LPSTR lpBuffer, LPSTR *lpFilePart) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetFullPathNameA(%s, %u)\n", lpFileName ? lpFileName : "(null)", nBufferLength);

	if (lpFilePart) {
		*lpFilePart = nullptr;
	}

	if (!lpFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}

	FullPathInfo info;
	if (!computeFullPath(lpFileName, info)) {
		return 0;
	}

	DEBUG_LOG(" -> %s\n", info.path.c_str());

	const size_t pathLen = info.path.size();
	const auto required = static_cast<DWORD>(pathLen + 1);

	if (nBufferLength == 0) {
		wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
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

	memcpy(lpBuffer, info.path.c_str(), pathLen);
	lpBuffer[pathLen] = '\0';

	if (lpFilePart) {
		if (info.filePartOffset != std::string::npos && info.filePartOffset < pathLen) {
			*lpFilePart = lpBuffer + info.filePartOffset;
		} else {
			*lpFilePart = nullptr;
		}
	}

	return static_cast<DWORD>(pathLen);
}

DWORD WIN_FUNC GetFullPathNameW(LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetFullPathNameW(%p, %u)\n", lpFileName, nBufferLength);

	if (lpFilePart) {
		*lpFilePart = nullptr;
	}

	if (!lpFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}

	std::string narrow = wideStringToString(lpFileName);
	FullPathInfo info;
	if (!computeFullPath(narrow, info)) {
		return 0;
	}

	DEBUG_LOG(" -> %s\n", info.path.c_str());

	auto widePath = stringToWideString(info.path.c_str());
	const size_t wideLen = widePath.size();
	const auto required = static_cast<DWORD>(wideLen);

	if (nBufferLength == 0) {
		wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
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

	if (lpFilePart) {
		if (info.filePartOffset != std::string::npos && info.filePartOffset < info.path.size()) {
			*lpFilePart = lpBuffer + info.filePartOffset;
		} else {
			*lpFilePart = nullptr;
		}
	}

	return static_cast<DWORD>(wideLen - 1);
}

DWORD WIN_FUNC GetShortPathNameA(LPCSTR lpszLongPath, LPSTR lpszShortPath, DWORD cchBuffer) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetShortPathNameA(%s)\n", lpszLongPath ? lpszLongPath : "(null)");
	if (!lpszLongPath || !lpszShortPath) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}

	std::filesystem::path absPath = std::filesystem::absolute(files::pathFromWindows(lpszLongPath));
	std::string absStr = files::pathToWindows(absPath);
	DWORD required = static_cast<DWORD>(absStr.length() + 1);
	if (cchBuffer < required) {
		wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
		return required;
	}

	strcpy(lpszShortPath, absStr.c_str());
	return required - 1;
}

DWORD WIN_FUNC GetShortPathNameW(LPCWSTR lpszLongPath, LPWSTR lpszShortPath, DWORD cchBuffer) {
	HOST_CONTEXT_GUARD();
	if (!lpszLongPath || !lpszShortPath) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	std::string longPath = wideStringToString(lpszLongPath);
	DEBUG_LOG("GetShortPathNameW(%s)\n", longPath.c_str());
	std::filesystem::path absPath = std::filesystem::absolute(files::pathFromWindows(longPath.c_str()));
	std::string absStr = files::pathToWindows(absPath);
	auto absStrW = stringToWideString(absStr.c_str());
	size_t len = wstrlen(absStrW.data());
	DWORD required = static_cast<DWORD>(len + 1);
	if (cchBuffer < required) {
		wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
		return required;
	}
	wstrncpy(lpszShortPath, absStrW.data(), len + 1);
	return static_cast<DWORD>(len);
}

UINT WIN_FUNC GetTempFileNameA(LPCSTR lpPathName, LPCSTR lpPrefixString, UINT uUnique, LPSTR lpTempFileName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetTempFileNameA(%s, %s, %u)\n", lpPathName ? lpPathName : "(null)",
			  lpPrefixString ? lpPrefixString : "(null)", uUnique);
	if (!lpPathName || !lpPrefixString || !lpTempFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	if (strlen(lpPathName) > MAX_PATH - 14) {
		wibo::lastError = ERROR_BUFFER_OVERFLOW;
		return 0;
	}
	char uniqueStr[20];
	std::filesystem::path path;

	if (uUnique == 0) {
		std::random_device rd;
		random_shorts_engine rse(rd());
		while (true) {
			uUnique = rse();
			if (uUnique == 0) {
				continue;
			}
			snprintf(uniqueStr, sizeof(uniqueStr), "%.3s%X.TMP", lpPrefixString, uUnique);
			path = files::pathFromWindows(lpPathName) / uniqueStr;
			int fd = open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0644);
			if (fd >= 0) {
				close(fd);
				break;
			}
		}
	} else {
		snprintf(uniqueStr, sizeof(uniqueStr), "%.3s%X.TMP", lpPrefixString, uUnique & 0xFFFF);
		path = files::pathFromWindows(lpPathName) / uniqueStr;
	}
	std::string str = files::pathToWindows(path);
	DEBUG_LOG(" -> %s\n", str.c_str());
	strncpy(lpTempFileName, str.c_str(), MAX_PATH);
	lpTempFileName[MAX_PATH - 1] = '\0';
	return uUnique;
}

DWORD WIN_FUNC GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetTempPathA(%u, %p)\n", nBufferLength, lpBuffer);

	if (nBufferLength == 0 || lpBuffer == nullptr) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		DEBUG_LOG(" -> ERROR_INVALID_PARAMETER\n");
		return 0;
	}

	const char *path = getenv("WIBO_TMP_DIR");
	if (!path) {
		path = "Z:\\tmp\\";
	}
	size_t len = strlen(path);
	if (len + 1 > nBufferLength) {
		wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
		DEBUG_LOG(" -> ERROR_INSUFFICIENT_BUFFER\n");
		return static_cast<DWORD>(len + 1);
	}

	DEBUG_LOG(" -> %s\n", path);
	strncpy(lpBuffer, path, nBufferLength);
	lpBuffer[nBufferLength - 1] = '\0';
	return static_cast<DWORD>(len);
}

HANDLE WIN_FUNC FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FindFirstFileA(%s, %p)", lpFileName ? lpFileName : "(null)", lpFindFileData);
	if (!lpFindFileData) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		DEBUG_LOG(" -> ERROR_INVALID_PARAMETER\n");
		return INVALID_HANDLE_VALUE;
	}
	if (!lpFileName) {
		wibo::lastError = ERROR_PATH_NOT_FOUND;
		DEBUG_LOG(" -> ERROR_PATH_NOT_FOUND\n");
		return INVALID_HANDLE_VALUE;
	}

	HANDLE handle = findFirstFileCommon(std::string(lpFileName), lpFindFileData);
	DEBUG_LOG(" -> %p\n", handle);
	return handle;
}

HANDLE WIN_FUNC FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FindFirstFileW(%p, %p)", lpFileName, lpFindFileData);
	if (!lpFindFileData) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		DEBUG_LOG(" -> ERROR_INVALID_PARAMETER\n");
		return INVALID_HANDLE_VALUE;
	}
	if (!lpFileName) {
		wibo::lastError = ERROR_PATH_NOT_FOUND;
		DEBUG_LOG(" -> ERROR_PATH_NOT_FOUND\n");
		return INVALID_HANDLE_VALUE;
	}

	std::string narrowName = wideStringToString(lpFileName);
	HANDLE handle = findFirstFileCommon(narrowName, lpFindFileData);
	DEBUG_LOG(" -> %p\n", handle);
	return handle;
}

HANDLE WIN_FUNC FindFirstFileExA(LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData,
								 FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FindFirstFileExA(%s, %d, %p, %d, %p, 0x%x)", lpFileName ? lpFileName : "(null)", fInfoLevelId,
			  lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
	if (!lpFindFileData) {
		DEBUG_LOG(" -> ERROR_INVALID_PARAMETER\n");
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return INVALID_HANDLE_VALUE;
	}
	if (!lpFileName) {
		DEBUG_LOG(" -> ERROR_PATH_NOT_FOUND\n");
		wibo::lastError = ERROR_PATH_NOT_FOUND;
		return INVALID_HANDLE_VALUE;
	}
	if (fInfoLevelId != FindExInfoStandard) {
		DEBUG_LOG(" -> ERROR_INVALID_PARAMETER\n");
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return INVALID_HANDLE_VALUE;
	}
	if (fSearchOp != FindExSearchNameMatch) {
		DEBUG_LOG(" -> ERROR_INVALID_PARAMETER\n");
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return INVALID_HANDLE_VALUE;
	}
	if (lpSearchFilter) {
		DEBUG_LOG(" -> ERROR_INVALID_PARAMETER\n");
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return INVALID_HANDLE_VALUE;
	}
	if (dwAdditionalFlags != 0) {
		DEBUG_LOG(" -> ERROR_INVALID_PARAMETER\n");
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return INVALID_HANDLE_VALUE;
	}

	auto *findData = static_cast<LPWIN32_FIND_DATAA>(lpFindFileData);
	return findFirstFileCommon(std::string(lpFileName), findData);
}

BOOL WIN_FUNC FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FindNextFileA(%p, %p)\n", hFindFile, lpFindFileData);
	if (!lpFindFileData) {
		DEBUG_LOG(" -> ERROR_INVALID_PARAMETER\n");
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	std::lock_guard lk(g_findHandleMutex);
	auto *state = lookupFindHandleLocked(hFindFile);
	if (!state) {
		DEBUG_LOG(" -> ERROR_INVALID_HANDLE\n");
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	if (state->singleResult || state->nextIndex >= state->entries.size()) {
		DEBUG_LOG(" -> ERROR_NO_MORE_FILES\n");
		wibo::lastError = ERROR_NO_MORE_FILES;
		return FALSE;
	}
	populateFindData(state->entries[state->nextIndex++], *lpFindFileData);
	return TRUE;
}

BOOL WIN_FUNC FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FindNextFileW(%p, %p)\n", hFindFile, lpFindFileData);
	if (!lpFindFileData) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	std::lock_guard lk(g_findHandleMutex);
	auto *state = lookupFindHandleLocked(hFindFile);
	if (!state) {
		DEBUG_LOG(" -> ERROR_INVALID_HANDLE\n");
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	if (state->singleResult || state->nextIndex >= state->entries.size()) {
		DEBUG_LOG(" -> ERROR_NO_MORE_FILES\n");
		wibo::lastError = ERROR_NO_MORE_FILES;
		return FALSE;
	}
	populateFindData(state->entries[state->nextIndex++], *lpFindFileData);
	return TRUE;
}

BOOL WIN_FUNC FindClose(HANDLE hFindFile) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FindClose(%p)\n", hFindFile);
	if (hFindFile == nullptr) {
		DEBUG_LOG(" -> ERROR_INVALID_HANDLE\n");
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}

	auto owned = detachFindHandle(hFindFile);
	if (!owned) {
		DEBUG_LOG(" -> ERROR_INVALID_HANDLE\n");
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	return TRUE;
}

} // namespace kernel32
