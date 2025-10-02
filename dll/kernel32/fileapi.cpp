#include "fileapi.h"

#include "errors.h"
#include "files.h"
#include "internal.h"
#include "strutil.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fnmatch.h>
#include <random>
#include <string>
#include <system_error>
#include <unistd.h>

namespace {

using random_shorts_engine =
	std::independent_bits_engine<std::default_random_engine, sizeof(unsigned short) * 8, unsigned short>;

constexpr uintptr_t kPseudoFindHandleValue = 1;
const HANDLE kPseudoFindHandle = reinterpret_cast<HANDLE>(kPseudoFindHandleValue);

constexpr uint64_t kWindowsTicksPerSecond = 10000000ULL;
constexpr uint64_t kSecondsBetween1601And1970 = 11644473600ULL;
const FILETIME kDefaultFindFileTime = {
	static_cast<DWORD>((kSecondsBetween1601And1970 * kWindowsTicksPerSecond) & 0xFFFFFFFFULL),
	static_cast<DWORD>((kSecondsBetween1601And1970 * kWindowsTicksPerSecond) >> 32)};

struct FindFirstFileHandle {
	std::filesystem::directory_iterator it;
	std::filesystem::directory_iterator end;
	std::string pattern;
};

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
		errno = ec.value();
		kernel32::setLastErrorFromErrno();
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

inline bool isPseudoHandle(HANDLE handle) { return reinterpret_cast<uintptr_t>(handle) == kPseudoFindHandleValue; }

inline void setCommonFindDataFields(WIN32_FIND_DATAA &data) {
	data.ftCreationTime = kDefaultFindFileTime;
	data.ftLastAccessTime = kDefaultFindFileTime;
	data.ftLastWriteTime = kDefaultFindFileTime;
	data.dwFileAttributes = 0;
	data.nFileSizeHigh = 0;
	data.nFileSizeLow = 0;
	data.dwReserved0 = 0;
	data.dwReserved1 = 0;
	data.cFileName[0] = '\0';
	data.cAlternateFileName[0] = '\0';
}

inline void setCommonFindDataFields(WIN32_FIND_DATAW &data) {
	data.ftCreationTime = kDefaultFindFileTime;
	data.ftLastAccessTime = kDefaultFindFileTime;
	data.ftLastWriteTime = kDefaultFindFileTime;
	data.dwFileAttributes = 0;
	data.nFileSizeHigh = 0;
	data.nFileSizeLow = 0;
	data.dwReserved0 = 0;
	data.dwReserved1 = 0;
	data.cFileName[0] = 0;
	data.cAlternateFileName[0] = 0;
}

DWORD computeAttributesAndSize(const std::filesystem::path &path, DWORD &sizeHigh, DWORD &sizeLow) {
	std::error_code ec;
	auto status = std::filesystem::status(path, ec);
	uint64_t fileSize = 0;
	DWORD attributes = 0;
	if (status.type() == std::filesystem::file_type::directory) {
		attributes |= FILE_ATTRIBUTE_DIRECTORY;
	}
	if (status.type() == std::filesystem::file_type::regular) {
		attributes |= FILE_ATTRIBUTE_NORMAL;
		fileSize = std::filesystem::file_size(path, ec);
	}
	sizeHigh = static_cast<DWORD>(fileSize >> 32);
	sizeLow = static_cast<DWORD>(fileSize);
	return attributes;
}

void setFindFileDataFromPath(const std::filesystem::path &path, WIN32_FIND_DATAA &data) {
	setCommonFindDataFields(data);
	data.dwFileAttributes = computeAttributesAndSize(path, data.nFileSizeHigh, data.nFileSizeLow);
	std::string fileName = path.filename().string();
	if (fileName.size() >= MAX_PATH) {
		fileName.resize(MAX_PATH - 1);
	}
	std::strncpy(data.cFileName, fileName.c_str(), MAX_PATH);
	data.cFileName[MAX_PATH - 1] = '\0';
	std::strncpy(data.cAlternateFileName, "8P3FMTFN.BAD", sizeof(data.cAlternateFileName));
	data.cAlternateFileName[sizeof(data.cAlternateFileName) - 1] = '\0';
}

void setFindFileDataFromPath(const std::filesystem::path &path, WIN32_FIND_DATAW &data) {
	setCommonFindDataFields(data);
	data.dwFileAttributes = computeAttributesAndSize(path, data.nFileSizeHigh, data.nFileSizeLow);
	std::string fileName = path.filename().string();
	auto wideName = stringToWideString(fileName.c_str());
	size_t copyLen = std::min<size_t>(MAX_PATH - 1, wstrlen(wideName.data()));
	wstrncpy(data.cFileName, wideName.data(), copyLen);
	data.cFileName[copyLen] = 0;
	auto wideAlt = stringToWideString("8P3FMTFN.BAD");
	copyLen = std::min<size_t>(sizeof(data.cAlternateFileName) / sizeof(data.cAlternateFileName[0]) - 1,
							   wstrlen(wideAlt.data()));
	wstrncpy(data.cAlternateFileName, wideAlt.data(), copyLen);
	data.cAlternateFileName[copyLen] = 0;
}

bool nextMatch(FindFirstFileHandle &handle, std::filesystem::path &outPath) {
	for (; handle.it != handle.end; ++handle.it) {
		const auto current = *handle.it;
		if (fnmatch(handle.pattern.c_str(), current.path().filename().c_str(), 0) == 0) {
			outPath = current.path();
			++handle.it;
			return true;
		}
	}
	return false;
}

bool initializeEnumeration(const std::filesystem::path &parent, const std::string &pattern, FindFirstFileHandle &handle,
						   std::filesystem::path &firstMatch) {
	if (pattern.empty()) {
		return false;
	}
	handle = FindFirstFileHandle{std::filesystem::directory_iterator(parent), std::filesystem::directory_iterator(),
								 pattern};
	return nextMatch(handle, firstMatch);
}

} // namespace

namespace kernel32 {

DWORD WIN_FUNC GetFullPathNameA(LPCSTR lpFileName, DWORD nBufferLength, LPSTR lpBuffer, LPSTR *lpFilePart) {
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

	wibo::lastError = ERROR_SUCCESS;
	return static_cast<DWORD>(pathLen);
}

DWORD WIN_FUNC GetFullPathNameW(LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart) {
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

	wibo::lastError = ERROR_SUCCESS;
	return static_cast<DWORD>(wideLen - 1);
}

DWORD WIN_FUNC GetShortPathNameA(LPCSTR lpszLongPath, LPSTR lpszShortPath, DWORD cchBuffer) {
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
	wibo::lastError = ERROR_SUCCESS;
	return required - 1;
}

DWORD WIN_FUNC GetShortPathNameW(LPCWSTR lpszLongPath, LPWSTR lpszShortPath, DWORD cchBuffer) {
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
	wibo::lastError = ERROR_SUCCESS;
	return static_cast<DWORD>(len);
}

UINT WIN_FUNC GetTempFileNameA(LPCSTR lpPathName, LPCSTR lpPrefixString, UINT uUnique, LPSTR lpTempFileName) {
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
	wibo::lastError = ERROR_SUCCESS;
	return uUnique;
}

DWORD WIN_FUNC GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer) {
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
	wibo::lastError = ERROR_SUCCESS;
	return static_cast<DWORD>(len);
}

HANDLE WIN_FUNC FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) {
	DEBUG_LOG("FindFirstFileA(%s, %p)", lpFileName ? lpFileName : "(null)", lpFindFileData);
	if (!lpFileName || !lpFindFileData) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		DEBUG_LOG(" -> ERROR_INVALID_PARAMETER\n");
		return INVALID_HANDLE_VALUE;
	}

	std::filesystem::path hostPath = files::pathFromWindows(lpFileName);
	DEBUG_LOG(" -> %s\n", hostPath.c_str());

	std::error_code ec;
	auto status = std::filesystem::status(hostPath, ec);
	setCommonFindDataFields(*lpFindFileData);
	if (status.type() == std::filesystem::file_type::regular) {
		setFindFileDataFromPath(hostPath, *lpFindFileData);
		wibo::lastError = ERROR_SUCCESS;
		return kPseudoFindHandle;
	}

	std::filesystem::path parent = hostPath.parent_path();
	if (parent.empty()) {
		parent = ".";
	}
	if (!std::filesystem::exists(parent)) {
		wibo::lastError = ERROR_PATH_NOT_FOUND;
		return INVALID_HANDLE_VALUE;
	}

	std::filesystem::path match;
	auto *handle = new FindFirstFileHandle();
	if (!initializeEnumeration(parent, hostPath.filename().string(), *handle, match)) {
		delete handle;
		wibo::lastError = ERROR_FILE_NOT_FOUND;
		return INVALID_HANDLE_VALUE;
	}

	setFindFileDataFromPath(match, *lpFindFileData);
	wibo::lastError = ERROR_SUCCESS;
	return reinterpret_cast<HANDLE>(handle);
}

HANDLE WIN_FUNC FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) {
	DEBUG_LOG("FindFirstFileW(%p, %p)", lpFileName, lpFindFileData);
	if (!lpFileName || !lpFindFileData) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		DEBUG_LOG(" -> ERROR_INVALID_PARAMETER\n");
		return INVALID_HANDLE_VALUE;
	}

	std::string narrowName = wideStringToString(lpFileName);
	std::filesystem::path hostPath = files::pathFromWindows(narrowName.c_str());
	DEBUG_LOG(", %s -> %s\n", narrowName.c_str(), hostPath.c_str());

	std::error_code ec;
	auto status = std::filesystem::status(hostPath, ec);
	setCommonFindDataFields(*lpFindFileData);
	if (status.type() == std::filesystem::file_type::regular) {
		setFindFileDataFromPath(hostPath, *lpFindFileData);
		wibo::lastError = ERROR_SUCCESS;
		return kPseudoFindHandle;
	}

	std::filesystem::path parent = hostPath.parent_path();
	if (parent.empty()) {
		parent = ".";
	}
	if (!std::filesystem::exists(parent)) {
		wibo::lastError = ERROR_PATH_NOT_FOUND;
		return INVALID_HANDLE_VALUE;
	}

	std::filesystem::path match;
	auto *handle = new FindFirstFileHandle();
	if (!initializeEnumeration(parent, hostPath.filename().string(), *handle, match)) {
		delete handle;
		wibo::lastError = ERROR_FILE_NOT_FOUND;
		return INVALID_HANDLE_VALUE;
	}

	setFindFileDataFromPath(match, *lpFindFileData);
	wibo::lastError = ERROR_SUCCESS;
	return reinterpret_cast<HANDLE>(handle);
}

HANDLE WIN_FUNC FindFirstFileExA(LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData,
								 FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags) {
	DEBUG_LOG("FindFirstFileExA(%s, %d, %p, %d, %p, 0x%x) -> ", lpFileName ? lpFileName : "(null)", fInfoLevelId,
			  lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
	(void)fInfoLevelId;
	(void)fSearchOp;
	(void)lpSearchFilter;
	(void)dwAdditionalFlags;
	return FindFirstFileA(lpFileName, static_cast<LPWIN32_FIND_DATAA>(lpFindFileData));
}

BOOL WIN_FUNC FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) {
	DEBUG_LOG("FindNextFileA(%p, %p)\n", hFindFile, lpFindFileData);
	if (!lpFindFileData) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	if (isPseudoHandle(hFindFile)) {
		wibo::lastError = ERROR_NO_MORE_FILES;
		return FALSE;
	}

	auto *handle = reinterpret_cast<FindFirstFileHandle *>(hFindFile);
	if (!handle) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}

	std::filesystem::path match;
	if (!nextMatch(*handle, match)) {
		wibo::lastError = ERROR_NO_MORE_FILES;
		return FALSE;
	}

	setFindFileDataFromPath(match, *lpFindFileData);
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) {
	DEBUG_LOG("FindNextFileW(%p, %p)\n", hFindFile, lpFindFileData);
	if (!lpFindFileData) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	if (isPseudoHandle(hFindFile)) {
		wibo::lastError = ERROR_NO_MORE_FILES;
		return FALSE;
	}

	auto *handle = reinterpret_cast<FindFirstFileHandle *>(hFindFile);
	if (!handle) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}

	std::filesystem::path match;
	if (!nextMatch(*handle, match)) {
		wibo::lastError = ERROR_NO_MORE_FILES;
		return FALSE;
	}

	setFindFileDataFromPath(match, *lpFindFileData);
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC FindClose(HANDLE hFindFile) {
	DEBUG_LOG("FindClose(%p)\n", hFindFile);
	if (isPseudoHandle(hFindFile) || hFindFile == nullptr) {
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	auto *handle = reinterpret_cast<FindFirstFileHandle *>(hFindFile);
	if (!handle) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	delete handle;
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

} // namespace kernel32
