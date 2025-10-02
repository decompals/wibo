#include "fileapi.h"

#include "errors.h"
#include "files.h"
#include "handles.h"
#include "internal.h"
#include "strutil.h"
#include "timeutil.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fnmatch.h>
#include <optional>
#include <random>
#include <string>
#include <sys/stat.h>
#include <sys/time.h>
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

const FILETIME kDefaultFileInformationTime = {static_cast<DWORD>(UNIX_TIME_ZERO & 0xFFFFFFFFULL),
											  static_cast<DWORD>(UNIX_TIME_ZERO >> 32)};

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
	auto *baseFile = files::fileHandleFromHandle(baseHandle);
	if (!baseFile) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		outHandle = INVALID_HANDLE_VALUE;
		return true;
	}
	HANDLE duplicated = files::duplicateFileHandle(baseFile, false);
	if (!duplicated) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		outHandle = INVALID_HANDLE_VALUE;
		return true;
	}
	wibo::lastError = ERROR_SUCCESS;
	outHandle = duplicated;
	return true;
}

} // namespace

namespace kernel32 {

int64_t getFileSizeFromHandle(HANDLE hFile) {
	FILE *fp = files::fpFromHandle(hFile);
	if (!fp) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return -1;
	}
	struct stat64 st{};
	fflush(fp);
	if (fstat64(fileno(fp), &st) == -1 || !S_ISREG(st.st_mode)) {
		setLastErrorFromErrno();
		return -1;
	}
	return st.st_size;
}

DWORD WIN_FUNC GetFileAttributesA(LPCSTR lpFileName) {
	if (!lpFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return INVALID_FILE_ATTRIBUTES;
	}
	std::filesystem::path path = files::pathFromWindows(lpFileName);
	std::string pathStr = path.string();
	DEBUG_LOG("GetFileAttributesA(%s) -> %s\n", lpFileName, pathStr.c_str());

	if (endsWith(pathStr, "/license.dat")) {
		DEBUG_LOG("MWCC license override\n");
		wibo::lastError = ERROR_SUCCESS;
		return FILE_ATTRIBUTE_NORMAL;
	}

	std::error_code ec;
	auto status = std::filesystem::status(path, ec);
	if (ec) {
		errno = ec.value();
		setLastErrorFromErrno();
		return INVALID_FILE_ATTRIBUTES;
	}

	wibo::lastError = ERROR_SUCCESS;
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
	DEBUG_LOG("GetFileAttributesW -> ");
	if (!lpFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return INVALID_FILE_ATTRIBUTES;
	}
	std::string str = wideStringToString(lpFileName);
	return GetFileAttributesA(str.c_str());
}

UINT WIN_FUNC GetDriveTypeA(LPCSTR lpRootPathName) {
	DEBUG_LOG("STUB: GetDriveTypeA(%s)\n", lpRootPathName ? lpRootPathName : "(null)");
	(void)lpRootPathName;
	wibo::lastError = ERROR_SUCCESS;
	return DRIVE_FIXED;
}

UINT WIN_FUNC GetDriveTypeW(LPCWSTR lpRootPathName) {
	DEBUG_LOG("STUB: GetDriveTypeW(%p)\n", lpRootPathName);
	(void)lpRootPathName;
	wibo::lastError = ERROR_SUCCESS;
	return DRIVE_FIXED;
}

BOOL WIN_FUNC GetVolumeInformationA(LPCSTR lpRootPathName, LPSTR lpVolumeNameBuffer, DWORD nVolumeNameSize,
									LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength,
									LPDWORD lpFileSystemFlags, LPSTR lpFileSystemNameBuffer,
									DWORD nFileSystemNameSize) {
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
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC GetVolumeInformationW(LPCWSTR lpRootPathName, LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize,
									LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength,
									LPDWORD lpFileSystemFlags, LPWSTR lpFileSystemNameBuffer,
									DWORD nFileSystemNameSize) {
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
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

LONG WIN_FUNC CompareFileTime(const FILETIME *lpFileTime1, const FILETIME *lpFileTime2) {
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
	DEBUG_LOG("WriteFile(%p, %u)\n", hFile, nNumberOfBytesToWrite);
	wibo::lastError = ERROR_SUCCESS;

	auto file = files::fileHandleFromHandle(hFile);
	if (!file || !file->fp) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}

	bool handleOverlapped = (file->flags & FILE_FLAG_OVERLAPPED) != 0;
	auto *overlapped = reinterpret_cast<OVERLAPPED *>(lpOverlapped);
	bool usingOverlapped = overlapped != nullptr;
	if (!usingOverlapped && lpNumberOfBytesWritten == nullptr) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	std::optional<uint64_t> offset;
	bool updateFilePointer = true;
	if (usingOverlapped) {
		offset = (static_cast<uint64_t>(overlapped->Offset) | (static_cast<uint64_t>(overlapped->OffsetHigh) << 32));
		overlapped->Internal = STATUS_PENDING;
		overlapped->InternalHigh = 0;
		updateFilePointer = !handleOverlapped;
		resetOverlappedEvent(overlapped);
	}

	auto io = files::write(file, lpBuffer, nNumberOfBytesToWrite, offset, updateFilePointer);
	DWORD completionStatus = STATUS_SUCCESS;
	if (io.unixError != 0) {
		completionStatus = wibo::winErrorFromErrno(io.unixError);
		wibo::lastError = completionStatus;
		if (lpNumberOfBytesWritten) {
			*lpNumberOfBytesWritten = static_cast<DWORD>(io.bytesTransferred);
		}
		if (usingOverlapped) {
			overlapped->Internal = completionStatus;
			overlapped->InternalHigh = io.bytesTransferred;
			signalOverlappedEvent(overlapped);
		}
		return FALSE;
	}

	if (lpNumberOfBytesWritten && (!handleOverlapped || !usingOverlapped)) {
		*lpNumberOfBytesWritten = static_cast<DWORD>(io.bytesTransferred);
	}

	if (usingOverlapped) {
		overlapped->Internal = completionStatus;
		overlapped->InternalHigh = io.bytesTransferred;
		if (!handleOverlapped) {
			uint64_t baseOffset = offset.value_or(0);
			uint64_t newOffset = baseOffset + io.bytesTransferred;
			overlapped->Offset = static_cast<DWORD>(newOffset & 0xFFFFFFFFu);
			overlapped->OffsetHigh = static_cast<DWORD>(newOffset >> 32);
		}
		signalOverlappedEvent(overlapped);
	}

	return (io.bytesTransferred == nNumberOfBytesToWrite) ? TRUE : FALSE;
}

BOOL WIN_FUNC FlushFileBuffers(HANDLE hFile) {
	DEBUG_LOG("FlushFileBuffers(%p)\n", hFile);
	auto data = handles::dataFromHandle(hFile, false);
	if (data.type != handles::TYPE_FILE || data.ptr == nullptr) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	auto file = reinterpret_cast<files::FileHandle *>(data.ptr);
	if (!file || !file->fp) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	FILE *fp = file->fp;
	if (fflush(fp) != 0) {
		wibo::lastError = ERROR_ACCESS_DENIED;
		return FALSE;
	}
	int fd = file->fd;
	if (fd >= 0 && fsync(fd) != 0) {
		wibo::lastError = ERROR_ACCESS_DENIED;
		return FALSE;
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead,
					   LPOVERLAPPED lpOverlapped) {
	DEBUG_LOG("ReadFile(%p, %u)\n", hFile, nNumberOfBytesToRead);
	wibo::lastError = ERROR_SUCCESS;

	auto file = files::fileHandleFromHandle(hFile);
	if (!file || !file->fp) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}

	bool handleOverlapped = (file->flags & FILE_FLAG_OVERLAPPED) != 0;
	auto *overlapped = reinterpret_cast<OVERLAPPED *>(lpOverlapped);
	bool usingOverlapped = overlapped != nullptr;
	if (!usingOverlapped && lpNumberOfBytesRead == nullptr) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	std::optional<uint64_t> offset;
	bool updateFilePointer = true;
	if (usingOverlapped) {
		offset = (static_cast<uint64_t>(overlapped->Offset) | (static_cast<uint64_t>(overlapped->OffsetHigh) << 32));
		overlapped->Internal = STATUS_PENDING;
		overlapped->InternalHigh = 0;
		updateFilePointer = !handleOverlapped;
		resetOverlappedEvent(overlapped);
	}

	auto io = files::read(file, lpBuffer, nNumberOfBytesToRead, offset, updateFilePointer);
	DWORD completionStatus = STATUS_SUCCESS;
	if (io.unixError != 0) {
		completionStatus = wibo::winErrorFromErrno(io.unixError);
		wibo::lastError = completionStatus;
		if (lpNumberOfBytesRead) {
			*lpNumberOfBytesRead = static_cast<DWORD>(io.bytesTransferred);
		}
		if (usingOverlapped) {
			overlapped->Internal = completionStatus;
			overlapped->InternalHigh = io.bytesTransferred;
			signalOverlappedEvent(overlapped);
		}
		return FALSE;
	}

	if (io.reachedEnd && io.bytesTransferred == 0 && handleOverlapped) {
		completionStatus = ERROR_HANDLE_EOF;
	}

	if (lpNumberOfBytesRead && (!handleOverlapped || !usingOverlapped)) {
		*lpNumberOfBytesRead = static_cast<DWORD>(io.bytesTransferred);
	}

	if (usingOverlapped) {
		overlapped->Internal = completionStatus;
		overlapped->InternalHigh = io.bytesTransferred;
		if (!handleOverlapped) {
			uint64_t baseOffset = offset.value_or(0);
			uint64_t newOffset = baseOffset + io.bytesTransferred;
			overlapped->Offset = static_cast<DWORD>(newOffset & 0xFFFFFFFFu);
			overlapped->OffsetHigh = static_cast<DWORD>(newOffset >> 32);
		}
		signalOverlappedEvent(overlapped);
	}

	return TRUE;
}

HANDLE WIN_FUNC CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
							LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
							DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
	(void)lpSecurityAttributes;
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
	std::string path = files::pathFromWindows(lpFileName);
	DEBUG_LOG("CreateFileA(filename=%s (%s), desiredAccess=0x%x, shareMode=%u, securityAttributes=%p, "
			  "creationDisposition=%u, flagsAndAttributes=%u)\n",
			  lpFileName, path.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition,
			  dwFlagsAndAttributes);

	wibo::lastError = ERROR_SUCCESS;
	bool fileExists = (access(path.c_str(), F_OK) == 0);
	bool shouldTruncate = false;
	switch (dwCreationDisposition) {
	case CREATE_ALWAYS:
		if (fileExists) {
			wibo::lastError = ERROR_ALREADY_EXISTS;
			shouldTruncate = true;
		}
		break;
	case CREATE_NEW:
		if (fileExists) {
			wibo::lastError = ERROR_FILE_EXISTS;
			return INVALID_HANDLE_VALUE;
		}
		break;
	case OPEN_ALWAYS:
		if (fileExists) {
			wibo::lastError = ERROR_ALREADY_EXISTS;
		}
		break;
	case OPEN_EXISTING:
		if (!fileExists) {
			wibo::lastError = ERROR_FILE_NOT_FOUND;
			return INVALID_HANDLE_VALUE;
		}
		break;
	case TRUNCATE_EXISTING:
		shouldTruncate = true;
		if (!fileExists) {
			wibo::lastError = ERROR_FILE_NOT_FOUND;
			return INVALID_HANDLE_VALUE;
		}
		break;
	default:
		assert(false);
	}

	FILE *fp = nullptr;
	if (dwDesiredAccess == GENERIC_READ) {
		fp = fopen(path.c_str(), "rb");
	} else if (dwDesiredAccess == GENERIC_WRITE) {
		if (shouldTruncate || !fileExists) {
			fp = fopen(path.c_str(), "wb");
		} else {
			fp = fopen(path.c_str(), "rb+");
		}
	} else if (dwDesiredAccess == (GENERIC_READ | GENERIC_WRITE)) {
		if (shouldTruncate || !fileExists) {
			fp = fopen(path.c_str(), "wb+");
		} else {
			fp = fopen(path.c_str(), "rb+");
		}
	} else {
		assert(false);
	}

	if (fp) {
		void *handle = files::allocFpHandle(fp, dwDesiredAccess, dwShareMode, dwFlagsAndAttributes, true);
		DEBUG_LOG("-> %p\n", handle);
		return handle;
	}
	setLastErrorFromErrno();
	return INVALID_HANDLE_VALUE;
}

HANDLE WIN_FUNC CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
							LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
							DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
	DEBUG_LOG("CreateFileW -> ");
	if (!lpFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return INVALID_HANDLE_VALUE;
	}
	std::string lpFileNameA = wideStringToString(lpFileName);
	HANDLE consoleHandle = INVALID_HANDLE_VALUE;
	if (tryOpenConsoleDevice(dwDesiredAccess, dwShareMode, dwCreationDisposition, dwFlagsAndAttributes, consoleHandle,
							 lpFileNameA)) {
		DEBUG_LOG("CreateFileW(console=%s, desiredAccess=0x%x, shareMode=%u, flags=0x%x) -> %p\n", lpFileNameA.c_str(),
				  dwDesiredAccess, dwShareMode, dwFlagsAndAttributes, consoleHandle);
		return consoleHandle;
	}
	return CreateFileA(lpFileNameA.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition,
					   dwFlagsAndAttributes, hTemplateFile);
}

BOOL WIN_FUNC DeleteFileA(LPCSTR lpFileName) {
	if (!lpFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		DEBUG_LOG("DeleteFileA(NULL) -> ERROR_INVALID_PARAMETER\n");
		return FALSE;
	}
	std::string path = files::pathFromWindows(lpFileName);
	DEBUG_LOG("DeleteFileA(%s) -> %s\n", lpFileName, path.c_str());
	if (unlink(path.c_str()) == 0) {
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	setLastErrorFromErrno();
	return FALSE;
}

BOOL WIN_FUNC DeleteFileW(LPCWSTR lpFileName) {
	DEBUG_LOG("DeleteFileW -> ");
	if (!lpFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	std::string name = wideStringToString(lpFileName);
	return DeleteFileA(name.c_str());
}

BOOL WIN_FUNC MoveFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName) {
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
		errno = ec.value();
		setLastErrorFromErrno();
		return FALSE;
	}
	std::filesystem::rename(fromPath, toPath, ec);
	if (ec) {
		errno = ec.value();
		setLastErrorFromErrno();
		return FALSE;
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC MoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName) {
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
	DEBUG_LOG("SetFilePointer(%p, %ld, %p, %u)\n", hFile, static_cast<long>(lDistanceToMove), lpDistanceToMoveHigh,
			  dwMoveMethod);
	if (hFile == nullptr) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return INVALID_SET_FILE_POINTER;
	}
	FILE *fp = files::fpFromHandle(hFile);
	if (!fp) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return INVALID_SET_FILE_POINTER;
	}
	int origin = SEEK_SET;
	if (dwMoveMethod == FILE_CURRENT) {
		origin = SEEK_CUR;
	} else if (dwMoveMethod == FILE_END) {
		origin = SEEK_END;
	}
	wibo::lastError = ERROR_SUCCESS;
	if (fseek(fp, lDistanceToMove, origin) < 0) {
		if (errno == EINVAL) {
			wibo::lastError = ERROR_NEGATIVE_SEEK;
		} else {
			wibo::lastError = ERROR_INVALID_PARAMETER;
		}
		return INVALID_SET_FILE_POINTER;
	}
	long position = ftell(fp);
	if (position < 0) {
		setLastErrorFromErrno();
		return INVALID_SET_FILE_POINTER;
	}
	if (lpDistanceToMoveHigh) {
		*lpDistanceToMoveHigh = static_cast<LONG>(static_cast<uint64_t>(position) >> 32);
	}
	return static_cast<DWORD>(static_cast<uint64_t>(position) & 0xFFFFFFFFu);
}

BOOL WIN_FUNC SetFilePointerEx(HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpNewFilePointer,
							   DWORD dwMoveMethod) {
	if (hFile == nullptr) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	FILE *fp = files::fpFromHandle(hFile);
	if (!fp) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	int origin = SEEK_SET;
	if (dwMoveMethod == FILE_CURRENT) {
		origin = SEEK_CUR;
	} else if (dwMoveMethod == FILE_END) {
		origin = SEEK_END;
	}
	wibo::lastError = ERROR_SUCCESS;
	if (fseeko(fp, static_cast<off_t>(liDistanceToMove), origin) < 0) {
		if (errno == EINVAL) {
			wibo::lastError = ERROR_NEGATIVE_SEEK;
		} else {
			wibo::lastError = ERROR_INVALID_PARAMETER;
		}
		return FALSE;
	}
	off_t position = ftello(fp);
	if (position < 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
	if (lpNewFilePointer) {
		*lpNewFilePointer = static_cast<LARGE_INTEGER>(position);
	}
	return TRUE;
}

BOOL WIN_FUNC SetEndOfFile(HANDLE hFile) {
	DEBUG_LOG("SetEndOfFile(%p)\n", hFile);
	FILE *fp = files::fpFromHandle(hFile);
	if (!fp) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	if (fflush(fp) != 0 || ftruncate(fileno(fp), ftell(fp)) != 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC CreateDirectoryA(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes) {
	(void)lpSecurityAttributes;
	if (!lpPathName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	std::string path = files::pathFromWindows(lpPathName);
	DEBUG_LOG("CreateDirectoryA(%s, %p)\n", path.c_str(), lpSecurityAttributes);
	if (mkdir(path.c_str(), 0755) == 0) {
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	setLastErrorFromErrno();
	return FALSE;
}

BOOL WIN_FUNC RemoveDirectoryA(LPCSTR lpPathName) {
	if (!lpPathName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	std::string path = files::pathFromWindows(lpPathName);
	DEBUG_LOG("RemoveDirectoryA(%s)\n", path.c_str());
	if (rmdir(path.c_str()) == 0) {
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	setLastErrorFromErrno();
	return FALSE;
}

BOOL WIN_FUNC SetFileAttributesA(LPCSTR lpFileName, DWORD dwFileAttributes) {
	(void)dwFileAttributes;
	if (!lpFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	DEBUG_LOG("SetFileAttributesA(%s, %u)\n", lpFileName, dwFileAttributes);
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

DWORD WIN_FUNC GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh) {
	DEBUG_LOG("GetFileSize(%p, %p) ", hFile, lpFileSizeHigh);
	int64_t size = getFileSizeFromHandle(hFile);
	if (size < 0) {
		if (lpFileSizeHigh) {
			*lpFileSizeHigh = 0;
		}
		return INVALID_FILE_SIZE;
	}
	uint64_t uSize = static_cast<uint64_t>(size);
	if (lpFileSizeHigh) {
		*lpFileSizeHigh = static_cast<DWORD>(uSize >> 32);
	}
	wibo::lastError = ERROR_SUCCESS;
	return static_cast<DWORD>(uSize & 0xFFFFFFFFu);
}

BOOL WIN_FUNC GetFileTime(HANDLE hFile, LPFILETIME lpCreationTime, LPFILETIME lpLastAccessTime,
						  LPFILETIME lpLastWriteTime) {
	DEBUG_LOG("GetFileTime(%p, %p, %p, %p)\n", hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime);
	auto file = files::fileHandleFromHandle(hFile);
	if (!file || !file->fp) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	struct stat st{};
	if (fstat(fileno(file->fp), &st) != 0) {
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
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC SetFileTime(HANDLE hFile, const FILETIME *lpCreationTime, const FILETIME *lpLastAccessTime,
						  const FILETIME *lpLastWriteTime) {
	DEBUG_LOG("SetFileTime(%p, %p, %p, %p)\n", hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime);
	FILE *fp = files::fpFromHandle(hFile);
	if (!fp) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	int fd = fileno(fp);
	if (fd < 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
	bool changeAccess = !shouldIgnoreFileTimeParam(lpLastAccessTime);
	bool changeWrite = !shouldIgnoreFileTimeParam(lpLastWriteTime);
	if (!changeAccess && !changeWrite) {
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	struct stat st{};
	if (fstat(fd, &st) != 0) {
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
	if (futimes(fd, tv) != 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
#else
	struct timespec times[2] = {accessSpec, writeSpec};
	if (futimens(fd, times) != 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
#endif
	if (!shouldIgnoreFileTimeParam(lpCreationTime) && lpCreationTime) {
		DEBUG_LOG("SetFileTime: creation time not supported\n");
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

BOOL WIN_FUNC GetFileInformationByHandle(HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation) {
	DEBUG_LOG("GetFileInformationByHandle(%p, %p)\n", hFile, lpFileInformation);
	FILE *fp = files::fpFromHandle(hFile);
	if (fp == nullptr) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}
	struct stat64 st{};
	if (fstat64(fileno(fp), &st) != 0) {
		setLastErrorFromErrno();
		return FALSE;
	}
	if (lpFileInformation) {
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
	}
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

DWORD WIN_FUNC GetFileType(HANDLE hFile) {
	DEBUG_LOG("GetFileType(%p) ", hFile);
	auto *file = files::fileHandleFromHandle(hFile);
	if (!file || file->fd < 0) {
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
	wibo::lastError = ERROR_SUCCESS;
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
