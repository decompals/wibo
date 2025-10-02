#include "common.h"
#include "errors.h"
#include "files.h"
#include "handles.h"
#include "kernel32/debugapi.h"
#include "kernel32/errhandlingapi.h"
#include "kernel32/fibersapi.h"
#include "kernel32/fileapi.h"
#include "kernel32/handleapi.h"
#include "kernel32/heapapi.h"
#include "kernel32/interlockedapi.h"
#include "kernel32/internal.h"
#include "kernel32/libloaderapi.h"
#include "kernel32/memoryapi.h"
#include "kernel32/minwinbase.h"
#include "kernel32/processenv.h"
#include "kernel32/processthreadsapi.h"
#include "kernel32/profileapi.h"
#include "kernel32/stringapiset.h"
#include "kernel32/synchapi.h"
#include "kernel32/sysinfoapi.h"
#include "kernel32/timeutil.h"
#include "kernel32/timezoneapi.h"
#include "kernel32/winbase.h"
#include "kernel32/wincon.h"
#include "kernel32/winnls.h"
#include "kernel32/wow64apiset.h"
#include "processes.h"
#include "resources.h"
#include "strutil.h"
#include <algorithm>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <functional>
#include <iterator>
#include <limits>
#include <mimalloc.h>
#include <new>
#include <pthread.h>
#include <spawn.h>
#include <string>
#include <strings.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <system_error>
#include <unistd.h>
#include <vector>

namespace kernel32 {

int64_t getFileSize(HANDLE hFile) {
	FILE *fp = files::fpFromHandle(hFile);
	if (!fp) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return -1; // INVALID_FILE_SIZE
	}
	struct stat64 st;
	fflush(fp);
	if (fstat64(fileno(fp), &st) == -1 || !S_ISREG(st.st_mode)) {
		setLastErrorFromErrno();
		return -1; // INVALID_FILE_SIZE
	}
	return st.st_size;
}

static const FILETIME defaultFiletime = {static_cast<DWORD>(UNIX_TIME_ZERO & 0xFFFFFFFFULL),
										 static_cast<DWORD>(UNIX_TIME_ZERO >> 32)};

unsigned int WIN_FUNC GetFileAttributesA(const char *lpFileName) {
	auto path = files::pathFromWindows(lpFileName);
	DEBUG_LOG("GetFileAttributesA(%s) -> %s\n", lpFileName, path.c_str());

	// See ole32::CoCreateInstance
	if (endsWith(path, "/license.dat")) {
		DEBUG_LOG("MWCC license override\n");
		return 0x80; // FILE_ATTRIBUTE_NORMAL
	}

	auto status = std::filesystem::status(path);

	wibo::lastError = 0;

	switch (status.type()) {
	case std::filesystem::file_type::regular:
		DEBUG_LOG("File exists\n");
		return 0x80; // FILE_ATTRIBUTE_NORMAL
	case std::filesystem::file_type::directory:
		return 0x10; // FILE_ATTRIBUTE_DIRECTORY
	case std::filesystem::file_type::not_found:
	default:
		DEBUG_LOG("File does not exist\n");
		wibo::lastError = 2; // ERROR_FILE_NOT_FOUND
		return 0xFFFFFFFF;	 // INVALID_FILE_ATTRIBUTES
	}
}

unsigned int WIN_FUNC GetFileAttributesW(const uint16_t *lpFileName) {
	DEBUG_LOG("GetFileAttributesW -> ");
	std::string str = wideStringToString(lpFileName);
	return GetFileAttributesA(str.c_str());
}

unsigned int WIN_FUNC WriteFile(void *hFile, const void *lpBuffer, unsigned int nNumberOfBytesToWrite,
								unsigned int *lpNumberOfBytesWritten, void *lpOverlapped) {
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

	return (io.bytesTransferred == nNumberOfBytesToWrite);
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

unsigned int WIN_FUNC ReadFile(void *hFile, void *lpBuffer, unsigned int nNumberOfBytesToRead,
							   unsigned int *lpNumberOfBytesRead, void *lpOverlapped) {
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

enum {
	CREATE_NEW = 1,
	CREATE_ALWAYS = 2,
	OPEN_EXISTING = 3,
	OPEN_ALWAYS = 4,
	TRUNCATE_EXISTING = 5,
};
void *WIN_FUNC CreateFileA(const char *lpFileName, unsigned int dwDesiredAccess, unsigned int dwShareMode,
						   void *lpSecurityAttributes, unsigned int dwCreationDisposition,
						   unsigned int dwFlagsAndAttributes, void *hTemplateFile) {
	std::string path = files::pathFromWindows(lpFileName);
	DEBUG_LOG("CreateFileA(filename=%s (%s), desiredAccess=0x%x, shareMode=%u, securityAttributes=%p, "
			  "creationDisposition=%u, flagsAndAttributes=%u)\n",
			  lpFileName, path.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition,
			  dwFlagsAndAttributes);

	wibo::lastError = 0; // possibly overwritten later in this function

	// Based on https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#parameters
	// and this table: https://stackoverflow.com/a/14469641
	bool fileExists = (access(path.c_str(), F_OK) == 0);
	bool shouldTruncate = false;
	switch (dwCreationDisposition) {
	case CREATE_ALWAYS:
		if (fileExists) {
			wibo::lastError = 183; // ERROR_ALREADY_EXISTS
			shouldTruncate = true; // "The function overwrites the file"
								   // Function succeeds
		}
		break;
	case CREATE_NEW:
		if (fileExists) {
			wibo::lastError = 80; // ERROR_FILE_EXISTS
			return INVALID_HANDLE_VALUE;
		}
		break;
	case OPEN_ALWAYS:
		if (fileExists) {
			wibo::lastError = 183; // ERROR_ALREADY_EXISTS
								   // Function succeeds
		}
		break;
	case OPEN_EXISTING:
		if (!fileExists) {
			wibo::lastError = 2; // ERROR_FILE_NOT_FOUND
			return INVALID_HANDLE_VALUE;
		}
		break;
	case TRUNCATE_EXISTING:
		shouldTruncate = true;
		if (!fileExists) {
			wibo::lastError = 2; // ERROR_FILE_NOT_FOUND
			return INVALID_HANDLE_VALUE;
		}
		break;
	default:
		assert(0);
	}

	FILE *fp;
	if (dwDesiredAccess == 0x80000000) { // read
		fp = fopen(path.c_str(), "rb");
	} else if (dwDesiredAccess == 0x40000000) { // write
		if (shouldTruncate || !fileExists) {
			fp = fopen(path.c_str(), "wb");
		} else {
			// There is no way to fopen with only write permissions
			// and without truncating the file...
			fp = fopen(path.c_str(), "rb+");
		}
	} else if (dwDesiredAccess == 0xc0000000) { // read/write
		if (shouldTruncate || !fileExists) {
			fp = fopen(path.c_str(), "wb+");
		} else {
			fp = fopen(path.c_str(), "rb+");
		}
	} else {
		assert(0);
	}

	if (fp) {
		void *handle = files::allocFpHandle(fp, dwDesiredAccess, dwShareMode, dwFlagsAndAttributes, true);
		DEBUG_LOG("-> %p\n", handle);
		return handle;
	} else {
		setLastErrorFromErrno();
		return INVALID_HANDLE_VALUE;
	}
}

void *WIN_FUNC CreateFileW(const uint16_t *lpFileName, unsigned int dwDesiredAccess, unsigned int dwShareMode,
						   void *lpSecurityAttributes, unsigned int dwCreationDisposition,
						   unsigned int dwFlagsAndAttributes, void *hTemplateFile) {
	DEBUG_LOG("CreateFileW -> ");
	const auto lpFileNameA = wideStringToString(lpFileName);
	return CreateFileA(lpFileNameA.c_str(), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition,
					   dwFlagsAndAttributes, hTemplateFile);
}

BOOL WIN_FUNC DeleteFileA(const char *lpFileName) {
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

BOOL WIN_FUNC DeleteFileW(const uint16_t *lpFileName) {
	DEBUG_LOG("DeleteFileW -> ");
	if (!lpFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		DEBUG_LOG("ERROR_INVALID_PARAMETER\n");
		return FALSE;
	}
	std::string name = wideStringToString(lpFileName);
	return DeleteFileA(name.c_str());
}

BOOL WIN_FUNC MoveFileA(const char *lpExistingFileName, const char *lpNewFileName) {
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

BOOL WIN_FUNC MoveFileW(const uint16_t *lpExistingFileName, const uint16_t *lpNewFileName) {
	DEBUG_LOG("MoveFileW -> ");
	if (!lpExistingFileName || !lpNewFileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		DEBUG_LOG("ERROR_INVALID_PARAMETER\n");
		return FALSE;
	}
	std::string from = wideStringToString(lpExistingFileName);
	std::string to = wideStringToString(lpNewFileName);
	return MoveFileA(from.c_str(), to.c_str());
}

DWORD WIN_FUNC SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod) {
	DEBUG_LOG("SetFilePointer(%p, %d, %d)\n", hFile, lDistanceToMove, dwMoveMethod);
	if (hFile == nullptr) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return INVALID_SET_FILE_POINTER;
	}
	assert(!lpDistanceToMoveHigh || *lpDistanceToMoveHigh == 0);
	FILE *fp = files::fpFromHandle(hFile);
	if (!fp) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return INVALID_SET_FILE_POINTER;
	}
	wibo::lastError = ERROR_SUCCESS;
	int r = fseek(fp, lDistanceToMove, dwMoveMethod == 0 ? SEEK_SET : dwMoveMethod == 1 ? SEEK_CUR : SEEK_END);

	if (r < 0) {
		if (errno == EINVAL)
			wibo::lastError = ERROR_NEGATIVE_SEEK;
		else
			wibo::lastError = ERROR_INVALID_PARAMETER;
		return INVALID_SET_FILE_POINTER;
	}

	r = ftell(fp);
	assert(r >= 0);
	return r;
}

BOOL WIN_FUNC SetFilePointerEx(HANDLE hFile, LARGE_INTEGER lDistanceToMove, PLARGE_INTEGER lpDistanceToMoveHigh,
							   DWORD dwMoveMethod) {
	if (hFile == nullptr) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return 0;
	}
	assert(!lpDistanceToMoveHigh || *lpDistanceToMoveHigh == 0);
	DEBUG_LOG("SetFilePointerEx(%p, %ld, %d)\n", hFile, lDistanceToMove, dwMoveMethod);
	FILE *fp = files::fpFromHandle(hFile);
	if (!fp) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return 0;
	}
	wibo::lastError = ERROR_SUCCESS;
	int r = fseeko64(fp, lDistanceToMove, dwMoveMethod == 0 ? SEEK_SET : dwMoveMethod == 1 ? SEEK_CUR : SEEK_END);

	if (r < 0) {
		if (errno == EINVAL)
			wibo::lastError = ERROR_NEGATIVE_SEEK;
		else
			wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	r = ftell(fp);
	assert(r >= 0);
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
	return TRUE;
}

int WIN_FUNC CreateDirectoryA(const char *lpPathName, void *lpSecurityAttributes) {
	std::string path = files::pathFromWindows(lpPathName);
	DEBUG_LOG("CreateDirectoryA(%s, %p)\n", path.c_str(), lpSecurityAttributes);
	return mkdir(path.c_str(), 0755) == 0;
}

int WIN_FUNC RemoveDirectoryA(const char *lpPathName) {
	std::string path = files::pathFromWindows(lpPathName);
	DEBUG_LOG("RemoveDirectoryA(%s)\n", path.c_str());
	return rmdir(path.c_str()) == 0;
}

int WIN_FUNC SetFileAttributesA(const char *lpPathName, unsigned int dwFileAttributes) {
	std::string path = files::pathFromWindows(lpPathName);
	DEBUG_LOG("SetFileAttributesA(%s, %u)\n", path.c_str(), dwFileAttributes);
	return 1;
}

DWORD WIN_FUNC GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh) {
	DEBUG_LOG("GetFileSize(%p, %p) ", hFile, lpFileSizeHigh);
	int64_t size = getFileSize(hFile);
	if (size == -1) {
		DEBUG_LOG("-> INVALID_FILE_SIZE\n");
		return 0xFFFFFFFF; // INVALID_FILE_SIZE
	}
	DEBUG_LOG("-> %ld\n", size);
	if (lpFileSizeHigh != nullptr) {
		*lpFileSizeHigh = size >> 32;
	}
	return static_cast<DWORD>(size);
}

/*
 * Time
 */
int WIN_FUNC GetFileTime(void *hFile, FILETIME *lpCreationTime, FILETIME *lpLastAccessTime, FILETIME *lpLastWriteTime) {
	DEBUG_LOG("GetFileTime(%p, %p, %p, %p)\n", hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime);
	FILE *fp = files::fpFromHandle(hFile);
	if (!fp) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return 0;
	}
	int fd = fileno(fp);
	if (fd < 0) {
		setLastErrorFromErrno();
		return 0;
	}
	struct stat st;
	if (fstat(fd, &st) != 0) {
		setLastErrorFromErrno();
		return 0;
	}
	auto makeFileTime = [](time_t sec, long nanos) {
		uint64_t ticks = UNIX_TIME_ZERO;
		ticks += static_cast<uint64_t>(sec) * 10000000ULL;
		ticks += static_cast<uint64_t>(nanos) / 100ULL;
		return fileTimeFromDuration(ticks);
	};
	if (lpCreationTime) {
#if defined(__APPLE__)
		*lpCreationTime = makeFileTime(st.st_ctimespec.tv_sec, st.st_ctimespec.tv_nsec);
#elif defined(__linux__)
		*lpCreationTime = makeFileTime(st.st_ctim.tv_sec, st.st_ctim.tv_nsec);
#else
		*lpCreationTime = makeFileTime(st.st_ctime, 0);
#endif
	}
	if (lpLastAccessTime) {
#if defined(__APPLE__)
		*lpLastAccessTime = makeFileTime(st.st_atimespec.tv_sec, st.st_atimespec.tv_nsec);
#elif defined(__linux__)
		*lpLastAccessTime = makeFileTime(st.st_atim.tv_sec, st.st_atim.tv_nsec);
#else
		*lpLastAccessTime = makeFileTime(st.st_atime, 0);
#endif
	}
	if (lpLastWriteTime) {
#if defined(__APPLE__)
		*lpLastWriteTime = makeFileTime(st.st_mtimespec.tv_sec, st.st_mtimespec.tv_nsec);
#elif defined(__linux__)
		*lpLastWriteTime = makeFileTime(st.st_mtim.tv_sec, st.st_mtim.tv_nsec);
#else
		*lpLastWriteTime = makeFileTime(st.st_mtime, 0);
#endif
	}
	wibo::lastError = ERROR_SUCCESS;
	return 1;
}

static struct timespec statAccessTimespec(const struct stat &st) {
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

static struct timespec statModifyTimespec(const struct stat &st) {
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

int WIN_FUNC SetFileTime(void *hFile, const FILETIME *lpCreationTime, const FILETIME *lpLastAccessTime,
						 const FILETIME *lpLastWriteTime) {
	DEBUG_LOG("SetFileTime(%p, %p, %p, %p)\n", hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime);
	FILE *fp = files::fpFromHandle(hFile);
	if (!fp) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return 0;
	}
	int fd = fileno(fp);
	if (fd < 0) {
		setLastErrorFromErrno();
		return 0;
	}
	bool changeAccess = !shouldIgnoreFileTimeParam(lpLastAccessTime);
	bool changeWrite = !shouldIgnoreFileTimeParam(lpLastWriteTime);
	if (!changeAccess && !changeWrite) {
		wibo::lastError = ERROR_SUCCESS;
		return 1;
	}
	struct stat st{};
	if (fstat(fd, &st) != 0) {
		setLastErrorFromErrno();
		return 0;
	}
	struct timespec accessSpec = statAccessTimespec(st);
	struct timespec writeSpec = statModifyTimespec(st);
	if (changeAccess) {
		int64_t seconds = 0;
		uint32_t hundreds = 0;
		if (!fileTimeToUnixParts(*lpLastAccessTime, seconds, hundreds) ||
			!unixPartsToTimespec(seconds, hundreds, accessSpec)) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return 0;
		}
	}
	if (changeWrite) {
		int64_t seconds = 0;
		uint32_t hundreds = 0;
		if (!fileTimeToUnixParts(*lpLastWriteTime, seconds, hundreds) ||
			!unixPartsToTimespec(seconds, hundreds, writeSpec)) {
			wibo::lastError = ERROR_INVALID_PARAMETER;
			return 0;
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
		return 0;
	}
#else
	struct timespec times[2] = {accessSpec, writeSpec};
	if (futimens(fd, times) != 0) {
		setLastErrorFromErrno();
		return 0;
	}
#endif
	if (!shouldIgnoreFileTimeParam(lpCreationTime) && lpCreationTime) {
		DEBUG_LOG("SetFileTime: creation time not supported\n");
	}
	wibo::lastError = ERROR_SUCCESS;
	return 1;
}

struct BY_HANDLE_FILE_INFORMATION {
	unsigned long dwFileAttributes;
	FILETIME ftCreationTime;
	FILETIME ftLastAccessTime;
	FILETIME ftLastWriteTime;
	unsigned long dwVolumeSerialNumber;
	unsigned long nFileSizeHigh;
	unsigned long nFileSizeLow;
	unsigned long nNumberOfLinks;
	unsigned long nFileIndexHigh;
	unsigned long nFileIndexLow;
};

int WIN_FUNC GetFileInformationByHandle(void *hFile, BY_HANDLE_FILE_INFORMATION *lpFileInformation) {
	DEBUG_LOG("GetFileInformationByHandle(%p, %p)\n", hFile, lpFileInformation);
	FILE *fp = files::fpFromHandle(hFile);
	if (fp == nullptr) {
		wibo::lastError = 6; // ERROR_INVALID_HANDLE
		return 0;
	}
	struct stat64 st{};
	if (fstat64(fileno(fp), &st)) {
		setLastErrorFromErrno();
		return 0;
	}

	if (lpFileInformation != nullptr) {
		lpFileInformation->dwFileAttributes = 0;
		if (S_ISDIR(st.st_mode)) {
			lpFileInformation->dwFileAttributes |= 0x10;
		}
		if (S_ISREG(st.st_mode)) {
			lpFileInformation->dwFileAttributes |= 0x80;
		}
		lpFileInformation->ftCreationTime = defaultFiletime;
		lpFileInformation->ftLastAccessTime = defaultFiletime;
		lpFileInformation->ftLastWriteTime = defaultFiletime;
		lpFileInformation->dwVolumeSerialNumber = 0;
		lpFileInformation->nFileSizeHigh = (unsigned long)(st.st_size >> 32);
		lpFileInformation->nFileSizeLow = (unsigned long)st.st_size;
		lpFileInformation->nNumberOfLinks = 0;
		lpFileInformation->nFileIndexHigh = 0;
		lpFileInformation->nFileIndexLow = 0;
	}
	return 1;
}

constexpr DWORD FILE_TYPE_UNKNOWN = 0x0000;
constexpr DWORD FILE_TYPE_DISK = 0x0001;
constexpr DWORD FILE_TYPE_CHAR = 0x0002;
constexpr DWORD FILE_TYPE_PIPE = 0x0003;

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

UINT WIN_FUNC SetHandleCount(UINT uNumber) {
	DEBUG_LOG("SetHandleCount(%u)\n", uNumber);
	return handles::MAX_HANDLES;
}

void WIN_FUNC Sleep(DWORD dwMilliseconds) {
	DEBUG_LOG("Sleep(%u)\n", dwMilliseconds);
	usleep(static_cast<useconds_t>(dwMilliseconds) * 1000);
}

unsigned int WIN_FUNC IsProcessorFeaturePresent(unsigned int processorFeature) {
	DEBUG_LOG("IsProcessorFeaturePresent(%u)\n", processorFeature);

	if (processorFeature == 0) // PF_FLOATING_POINT_PRECISION_ERRATA
		return 1;
	if (processorFeature == 10) // PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
		return 1;
	if (processorFeature == 23) // PF_FASTFAIL_AVAILABLE (__fastfail() supported)
		return 1;

	// sure.. we have that feature...
	DEBUG_LOG("  IsProcessorFeaturePresent: we don't know about feature %u, lying...\n", processorFeature);
	return 1;
}

unsigned int WIN_FUNC FormatMessageA(unsigned int dwFlags, void *lpSource, unsigned int dwMessageId,
									 unsigned int dwLanguageId, char *lpBuffer, unsigned int nSize, va_list *argument) {
	DEBUG_LOG("FormatMessageA(%u, %p, %u, %u, %p, %u, %p)\n", dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer,
			  nSize, argument);

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
		std::string message = std::system_category().message(dwMessageId);
		size_t length = message.length();
		strcpy(lpBuffer, message.c_str());
		return length;
	} else if (dwFlags & 0x00000200) {
		// FORMAT_MESSAGE_IGNORE_INSERTS
	} else {
		// unhandled?
	}

	*lpBuffer = '\0';
	return 0;
}

int WIN_FUNC GetComputerNameA(char *lpBuffer, unsigned int *nSize) {
	DEBUG_LOG("GetComputerNameA(%p, %p)\n", lpBuffer, nSize);
	if (!nSize || !lpBuffer) {
		if (nSize) {
			*nSize = 0;
		}
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	constexpr unsigned int required = 9; // "COMPNAME" + null terminator
	if (*nSize < required) {
		*nSize = required;
		wibo::lastError = ERROR_BUFFER_OVERFLOW;
		return 0;
	}
	strcpy(lpBuffer, "COMPNAME");
	*nSize = required - 1;
	wibo::lastError = ERROR_SUCCESS;
	return 1;
}

int WIN_FUNC GetComputerNameW(uint16_t *lpBuffer, unsigned int *nSize) {
	DEBUG_LOG("GetComputerNameW(%p, %p)\n", lpBuffer, nSize);
	if (!nSize || !lpBuffer) {
		if (nSize) {
			*nSize = 0;
		}
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}
	constexpr uint16_t computerName[] = {'C', 'O', 'M', 'P', 'N', 'A', 'M', 'E', 0};
	constexpr unsigned int nameLength = 8;
	constexpr unsigned int required = nameLength + 1;
	if (*nSize < required) {
		*nSize = required;
		wibo::lastError = ERROR_BUFFER_OVERFLOW;
		return 0;
	}
	wstrncpy(lpBuffer, computerName, required);
	*nSize = nameLength;
	wibo::lastError = ERROR_SUCCESS;
	return 1;
}

void *WIN_FUNC EncodePointer(void *Ptr) {
	DEBUG_LOG("EncodePointer(%p)\n", Ptr);
	return Ptr;
}

void *WIN_FUNC DecodePointer(void *Ptr) {
	DEBUG_LOG("DecodePointer(%p)\n", Ptr);
	return Ptr;
}

BOOL WIN_FUNC SetDllDirectoryA(LPCSTR lpPathName) {
	DEBUG_LOG("SetDllDirectoryA(%s)\n", lpPathName);
	if (!lpPathName || lpPathName[0] == '\0') {
		wibo::clearDllDirectoryOverride();
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}

	auto hostPath = files::pathFromWindows(lpPathName);
	if (hostPath.empty() || !std::filesystem::exists(hostPath)) {
		wibo::lastError = ERROR_PATH_NOT_FOUND;
		return FALSE;
	}

	wibo::setDllDirectoryOverride(std::filesystem::absolute(hostPath));
	wibo::lastError = ERROR_SUCCESS;
	return TRUE;
}

void WIN_FUNC RtlUnwind(void *TargetFrame, void *TargetIp, EXCEPTION_RECORD *ExceptionRecord, void *ReturnValue) {
	DEBUG_LOG("RtlUnwind(%p, %p, %p, %p)\n", TargetFrame, TargetIp, ExceptionRecord, ReturnValue);
	DEBUG_LOG("WARNING: Silently returning from RtlUnwind - exception handlers and clean up code may not be run");
}

BOOL WIN_FUNC GetOverlappedResult(HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred,
								  BOOL bWait) {
	DEBUG_LOG("GetOverlappedResult(%p, %p, %p, %d)\n", hFile, lpOverlapped, lpNumberOfBytesTransferred, bWait);
	(void)hFile;
	if (!lpOverlapped) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	if (bWait && lpOverlapped->Internal == STATUS_PENDING) {
		if (lpOverlapped->hEvent) {
			WaitForSingleObject(lpOverlapped->hEvent, 0xFFFFFFFF);
		}
	}

	const auto status = static_cast<NTSTATUS>(lpOverlapped->Internal);
	if (status == STATUS_PENDING) {
		wibo::lastError = ERROR_IO_INCOMPLETE;
		if (lpNumberOfBytesTransferred) {
			*lpNumberOfBytesTransferred = static_cast<int>(lpOverlapped->InternalHigh);
		}
		return FALSE;
	}

	if (lpNumberOfBytesTransferred) {
		*lpNumberOfBytesTransferred = static_cast<int>(lpOverlapped->InternalHigh);
	}

	if (status == STATUS_SUCCESS) {
		wibo::lastError = ERROR_SUCCESS;
		return TRUE;
	}
	if (status == STATUS_END_OF_FILE || status == ERROR_HANDLE_EOF) {
		wibo::lastError = ERROR_HANDLE_EOF;
		return FALSE;
	}

	wibo::lastError = status;
	return FALSE;
}
} // namespace kernel32

static void *resolveByName(const char *name) {
	// errhandlingapi.h
	if (strcmp(name, "GetLastError") == 0)
		return (void *)kernel32::GetLastError;
	if (strcmp(name, "SetLastError") == 0)
		return (void *)kernel32::SetLastError;
	if (strcmp(name, "IsBadReadPtr") == 0)
		return (void *)kernel32::IsBadReadPtr;
	if (strcmp(name, "IsBadWritePtr") == 0)
		return (void *)kernel32::IsBadWritePtr;
	if (strcmp(name, "Wow64DisableWow64FsRedirection") == 0)
		return (void *)kernel32::Wow64DisableWow64FsRedirection;
	if (strcmp(name, "Wow64RevertWow64FsRedirection") == 0)
		return (void *)kernel32::Wow64RevertWow64FsRedirection;
	if (strcmp(name, "IsWow64Process") == 0)
		return (void *)kernel32::IsWow64Process;
	if (strcmp(name, "RaiseException") == 0)
		return (void *)kernel32::RaiseException;
	if (strcmp(name, "AddVectoredExceptionHandler") == 0)
		return (void *)kernel32::AddVectoredExceptionHandler;

	// processthreadsapi.h
	if (strcmp(name, "IsProcessorFeaturePresent") == 0)
		return (void *)kernel32::IsProcessorFeaturePresent;
	if (strcmp(name, "GetCurrentProcess") == 0)
		return (void *)kernel32::GetCurrentProcess;
	if (strcmp(name, "GetCurrentProcessId") == 0)
		return (void *)kernel32::GetCurrentProcessId;
	if (strcmp(name, "GetCurrentThreadId") == 0)
		return (void *)kernel32::GetCurrentThreadId;
	if (strcmp(name, "ExitProcess") == 0)
		return (void *)kernel32::ExitProcess;
	if (strcmp(name, "TerminateProcess") == 0)
		return (void *)kernel32::TerminateProcess;
	if (strcmp(name, "GetExitCodeProcess") == 0)
		return (void *)kernel32::GetExitCodeProcess;
	if (strcmp(name, "CreateProcessW") == 0)
		return (void *)kernel32::CreateProcessW;
	if (strcmp(name, "CreateProcessA") == 0)
		return (void *)kernel32::CreateProcessA;
	if (strcmp(name, "CreateThread") == 0)
		return (void *)kernel32::CreateThread;
	if (strcmp(name, "ExitThread") == 0)
		return (void *)kernel32::ExitThread;
	if (strcmp(name, "GetExitCodeThread") == 0)
		return (void *)kernel32::GetExitCodeThread;
	if (strcmp(name, "TlsAlloc") == 0)
		return (void *)kernel32::TlsAlloc;
	if (strcmp(name, "TlsFree") == 0)
		return (void *)kernel32::TlsFree;
	if (strcmp(name, "TlsGetValue") == 0)
		return (void *)kernel32::TlsGetValue;
	if (strcmp(name, "TlsSetValue") == 0)
		return (void *)kernel32::TlsSetValue;
	if (strcmp(name, "GetStartupInfoA") == 0)
		return (void *)kernel32::GetStartupInfoA;
	if (strcmp(name, "GetStartupInfoW") == 0)
		return (void *)kernel32::GetStartupInfoW;
	if (strcmp(name, "SetThreadStackGuarantee") == 0)
		return (void *)kernel32::SetThreadStackGuarantee;
	if (strcmp(name, "GetCurrentThread") == 0)
		return (void *)kernel32::GetCurrentThread;
	if (strcmp(name, "GetThreadTimes") == 0)
		return (void *)kernel32::GetThreadTimes;
	if (strcmp(name, "SetThreadDescription") == 0)
		return (void *)kernel32::SetThreadDescription;

	// winnls.h
	if (strcmp(name, "GetSystemDefaultLangID") == 0)
		return (void *)kernel32::GetSystemDefaultLangID;
	if (strcmp(name, "GetUserDefaultUILanguage") == 0)
		return (void *)kernel32::GetUserDefaultUILanguage;
	if (strcmp(name, "GetACP") == 0)
		return (void *)kernel32::GetACP;
	if (strcmp(name, "GetCPInfo") == 0)
		return (void *)kernel32::GetCPInfo;
	if (strcmp(name, "CompareStringA") == 0)
		return (void *)kernel32::CompareStringA;
	if (strcmp(name, "CompareStringW") == 0)
		return (void *)kernel32::CompareStringW;
	if (strcmp(name, "IsValidLocale") == 0)
		return (void *)kernel32::IsValidLocale;
	if (strcmp(name, "IsValidCodePage") == 0)
		return (void *)kernel32::IsValidCodePage;
	if (strcmp(name, "LCMapStringW") == 0)
		return (void *)kernel32::LCMapStringW;
	if (strcmp(name, "LCMapStringA") == 0)
		return (void *)kernel32::LCMapStringA;
	if (strcmp(name, "GetLocaleInfoA") == 0)
		return (void *)kernel32::GetLocaleInfoA;
	if (strcmp(name, "GetLocaleInfoW") == 0)
		return (void *)kernel32::GetLocaleInfoW;
	if (strcmp(name, "EnumSystemLocalesA") == 0)
		return (void *)kernel32::EnumSystemLocalesA;
	if (strcmp(name, "GetUserDefaultLCID") == 0)
		return (void *)kernel32::GetUserDefaultLCID;
	if (strcmp(name, "IsDBCSLeadByte") == 0)
		return (void *)kernel32::IsDBCSLeadByte;
	if (strcmp(name, "IsDBCSLeadByteEx") == 0)
		return (void *)kernel32::IsDBCSLeadByteEx;

	// synchapi.h
	if (strcmp(name, "InitializeCriticalSection") == 0)
		return (void *)kernel32::InitializeCriticalSection;
	if (strcmp(name, "InitializeCriticalSectionEx") == 0)
		return (void *)kernel32::InitializeCriticalSectionEx;
	if (strcmp(name, "InitializeCriticalSectionAndSpinCount") == 0)
		return (void *)kernel32::InitializeCriticalSectionAndSpinCount;
	if (strcmp(name, "DeleteCriticalSection") == 0)
		return (void *)kernel32::DeleteCriticalSection;
	if (strcmp(name, "EnterCriticalSection") == 0)
		return (void *)kernel32::EnterCriticalSection;
	if (strcmp(name, "LeaveCriticalSection") == 0)
		return (void *)kernel32::LeaveCriticalSection;
	if (strcmp(name, "InitOnceBeginInitialize") == 0)
		return (void *)kernel32::InitOnceBeginInitialize;
	if (strcmp(name, "InitOnceComplete") == 0)
		return (void *)kernel32::InitOnceComplete;
	if (strcmp(name, "AcquireSRWLockShared") == 0)
		return (void *)kernel32::AcquireSRWLockShared;
	if (strcmp(name, "ReleaseSRWLockShared") == 0)
		return (void *)kernel32::ReleaseSRWLockShared;
	if (strcmp(name, "AcquireSRWLockExclusive") == 0)
		return (void *)kernel32::AcquireSRWLockExclusive;
	if (strcmp(name, "ReleaseSRWLockExclusive") == 0)
		return (void *)kernel32::ReleaseSRWLockExclusive;
	if (strcmp(name, "TryAcquireSRWLockExclusive") == 0)
		return (void *)kernel32::TryAcquireSRWLockExclusive;
	if (strcmp(name, "WaitForSingleObject") == 0)
		return (void *)kernel32::WaitForSingleObject;
	if (strcmp(name, "CreateMutexA") == 0)
		return (void *)kernel32::CreateMutexA;
	if (strcmp(name, "CreateMutexW") == 0)
		return (void *)kernel32::CreateMutexW;
	if (strcmp(name, "CreateEventA") == 0)
		return (void *)kernel32::CreateEventA;
	if (strcmp(name, "CreateEventW") == 0)
		return (void *)kernel32::CreateEventW;
	if (strcmp(name, "CreateSemaphoreA") == 0)
		return (void *)kernel32::CreateSemaphoreA;
	if (strcmp(name, "CreateSemaphoreW") == 0)
		return (void *)kernel32::CreateSemaphoreW;
	if (strcmp(name, "SetEvent") == 0)
		return (void *)kernel32::SetEvent;
	if (strcmp(name, "ResetEvent") == 0)
		return (void *)kernel32::ResetEvent;
	if (strcmp(name, "ReleaseMutex") == 0)
		return (void *)kernel32::ReleaseMutex;
	if (strcmp(name, "ReleaseSemaphore") == 0)
		return (void *)kernel32::ReleaseSemaphore;
	if (strcmp(name, "SetThreadAffinityMask") == 0)
		return (void *)kernel32::SetThreadAffinityMask;
	if (strcmp(name, "ResumeThread") == 0)
		return (void *)kernel32::ResumeThread;
	if (strcmp(name, "SetThreadPriority") == 0)
		return (void *)kernel32::SetThreadPriority;
	if (strcmp(name, "GetThreadPriority") == 0)
		return (void *)kernel32::GetThreadPriority;

	// winbase.h
	if (strcmp(name, "GlobalAlloc") == 0)
		return (void *)kernel32::GlobalAlloc;
	if (strcmp(name, "GlobalReAlloc") == 0)
		return (void *)kernel32::GlobalReAlloc;
	if (strcmp(name, "GlobalFree") == 0)
		return (void *)kernel32::GlobalFree;
	if (strcmp(name, "GlobalFlags") == 0)
		return (void *)kernel32::GlobalFlags;
	if (strcmp(name, "LocalAlloc") == 0)
		return (void *)kernel32::LocalAlloc;
	if (strcmp(name, "LocalReAlloc") == 0)
		return (void *)kernel32::LocalReAlloc;
	if (strcmp(name, "LocalFree") == 0)
		return (void *)kernel32::LocalFree;
	if (strcmp(name, "LocalHandle") == 0)
		return (void *)kernel32::LocalHandle;
	if (strcmp(name, "LocalLock") == 0)
		return (void *)kernel32::LocalLock;
	if (strcmp(name, "LocalUnlock") == 0)
		return (void *)kernel32::LocalUnlock;
	if (strcmp(name, "LocalSize") == 0)
		return (void *)kernel32::LocalSize;
	if (strcmp(name, "LocalFlags") == 0)
		return (void *)kernel32::LocalFlags;
	if (strcmp(name, "GetCurrentDirectoryA") == 0)
		return (void *)kernel32::GetCurrentDirectoryA;
	if (strcmp(name, "GetCurrentDirectoryW") == 0)
		return (void *)kernel32::GetCurrentDirectoryW;
	if (strcmp(name, "SetCurrentDirectoryA") == 0)
		return (void *)kernel32::SetCurrentDirectoryA;
	if (strcmp(name, "SetCurrentDirectoryW") == 0)
		return (void *)kernel32::SetCurrentDirectoryW;
	if (strcmp(name, "FindResourceA") == 0)
		return (void *)kernel32::FindResourceA;
	if (strcmp(name, "FindResourceExA") == 0)
		return (void *)kernel32::FindResourceExA;
	if (strcmp(name, "FindResourceW") == 0)
		return (void *)kernel32::FindResourceW;
	if (strcmp(name, "FindResourceExW") == 0)
		return (void *)kernel32::FindResourceExW;
	if (strcmp(name, "SetHandleCount") == 0)
		return (void *)kernel32::SetHandleCount;
	if (strcmp(name, "GetProcessAffinityMask") == 0)
		return (void *)kernel32::GetProcessAffinityMask;
	if (strcmp(name, "SetProcessAffinityMask") == 0)
		return (void *)kernel32::SetProcessAffinityMask;
	if (strcmp(name, "FormatMessageA") == 0)
		return (void *)kernel32::FormatMessageA;
	if (strcmp(name, "GetComputerNameA") == 0)
		return (void *)kernel32::GetComputerNameA;
	if (strcmp(name, "GetComputerNameW") == 0)
		return (void *)kernel32::GetComputerNameW;
	if (strcmp(name, "EncodePointer") == 0)
		return (void *)kernel32::EncodePointer;
	if (strcmp(name, "DecodePointer") == 0)
		return (void *)kernel32::DecodePointer;
	if (strcmp(name, "SetDllDirectoryA") == 0)
		return (void *)kernel32::SetDllDirectoryA;
	if (strcmp(name, "Sleep") == 0)
		return (void *)kernel32::Sleep;

	// processenv.h
	if (strcmp(name, "GetCommandLineA") == 0)
		return (void *)kernel32::GetCommandLineA;
	if (strcmp(name, "GetCommandLineW") == 0)
		return (void *)kernel32::GetCommandLineW;
	if (strcmp(name, "GetEnvironmentStrings") == 0)
		return (void *)kernel32::GetEnvironmentStrings;
	if (strcmp(name, "FreeEnvironmentStringsA") == 0)
		return (void *)kernel32::FreeEnvironmentStringsA;
	if (strcmp(name, "GetEnvironmentStringsW") == 0)
		return (void *)kernel32::GetEnvironmentStringsW;
	if (strcmp(name, "FreeEnvironmentStringsW") == 0)
		return (void *)kernel32::FreeEnvironmentStringsW;
	if (strcmp(name, "GetEnvironmentVariableA") == 0)
		return (void *)kernel32::GetEnvironmentVariableA;
	if (strcmp(name, "SetEnvironmentVariableA") == 0)
		return (void *)kernel32::SetEnvironmentVariableA;
	if (strcmp(name, "SetEnvironmentVariableW") == 0)
		return (void *)kernel32::SetEnvironmentVariableW;
	if (strcmp(name, "GetEnvironmentVariableW") == 0)
		return (void *)kernel32::GetEnvironmentVariableW;

	// console api
	if (strcmp(name, "GetStdHandle") == 0)
		return (void *)kernel32::GetStdHandle;
	if (strcmp(name, "SetStdHandle") == 0)
		return (void *)kernel32::SetStdHandle;
	if (strcmp(name, "DuplicateHandle") == 0)
		return (void *)kernel32::DuplicateHandle;
	if (strcmp(name, "CloseHandle") == 0)
		return (void *)kernel32::CloseHandle;
	if (strcmp(name, "GetConsoleMode") == 0)
		return (void *)kernel32::GetConsoleMode;
	if (strcmp(name, "SetConsoleMode") == 0)
		return (void *)kernel32::SetConsoleMode;
	if (strcmp(name, "SetConsoleCtrlHandler") == 0)
		return (void *)kernel32::SetConsoleCtrlHandler;
	if (strcmp(name, "GetConsoleScreenBufferInfo") == 0)
		return (void *)kernel32::GetConsoleScreenBufferInfo;
	if (strcmp(name, "WriteConsoleW") == 0)
		return (void *)kernel32::WriteConsoleW;
	if (strcmp(name, "GetConsoleOutputCP") == 0)
		return (void *)kernel32::GetConsoleOutputCP;
	if (strcmp(name, "PeekConsoleInputA") == 0)
		return (void *)kernel32::PeekConsoleInputA;
	if (strcmp(name, "ReadConsoleInputA") == 0)
		return (void *)kernel32::ReadConsoleInputA;

	// fileapi.h
	if (strcmp(name, "GetFullPathNameA") == 0)
		return (void *)kernel32::GetFullPathNameA;
	if (strcmp(name, "GetFullPathNameW") == 0)
		return (void *)kernel32::GetFullPathNameW;
	if (strcmp(name, "GetShortPathNameA") == 0)
		return (void *)kernel32::GetShortPathNameA;
	if (strcmp(name, "GetShortPathNameW") == 0)
		return (void *)kernel32::GetShortPathNameW;
	if (strcmp(name, "FindFirstFileA") == 0)
		return (void *)kernel32::FindFirstFileA;
	if (strcmp(name, "FindFirstFileW") == 0)
		return (void *)kernel32::FindFirstFileW;
	if (strcmp(name, "FindFirstFileExA") == 0)
		return (void *)kernel32::FindFirstFileExA;
	if (strcmp(name, "FindNextFileA") == 0)
		return (void *)kernel32::FindNextFileA;
	if (strcmp(name, "FindNextFileW") == 0)
		return (void *)kernel32::FindNextFileW;
	if (strcmp(name, "FindClose") == 0)
		return (void *)kernel32::FindClose;
	if (strcmp(name, "GetFileAttributesA") == 0)
		return (void *)kernel32::GetFileAttributesA;
	if (strcmp(name, "GetFileAttributesW") == 0)
		return (void *)kernel32::GetFileAttributesW;
	if (strcmp(name, "WriteFile") == 0)
		return (void *)kernel32::WriteFile;
	if (strcmp(name, "FlushFileBuffers") == 0)
		return (void *)kernel32::FlushFileBuffers;
	if (strcmp(name, "ReadFile") == 0)
		return (void *)kernel32::ReadFile;
	if (strcmp(name, "CreateFileA") == 0)
		return (void *)kernel32::CreateFileA;
	if (strcmp(name, "CreateFileW") == 0)
		return (void *)kernel32::CreateFileW;
	if (strcmp(name, "CreateFileMappingA") == 0)
		return (void *)kernel32::CreateFileMappingA;
	if (strcmp(name, "CreateFileMappingW") == 0)
		return (void *)kernel32::CreateFileMappingW;
	if (strcmp(name, "MapViewOfFile") == 0)
		return (void *)kernel32::MapViewOfFile;
	if (strcmp(name, "UnmapViewOfFile") == 0)
		return (void *)kernel32::UnmapViewOfFile;
	if (strcmp(name, "DeleteFileA") == 0)
		return (void *)kernel32::DeleteFileA;
	if (strcmp(name, "DeleteFileW") == 0)
		return (void *)kernel32::DeleteFileW;
	if (strcmp(name, "MoveFileA") == 0)
		return (void *)kernel32::MoveFileA;
	if (strcmp(name, "MoveFileW") == 0)
		return (void *)kernel32::MoveFileW;
	if (strcmp(name, "SetFilePointer") == 0)
		return (void *)kernel32::SetFilePointer;
	if (strcmp(name, "SetFilePointerEx") == 0)
		return (void *)kernel32::SetFilePointerEx;
	if (strcmp(name, "SetEndOfFile") == 0)
		return (void *)kernel32::SetEndOfFile;
	if (strcmp(name, "CreateDirectoryA") == 0)
		return (void *)kernel32::CreateDirectoryA;
	if (strcmp(name, "RemoveDirectoryA") == 0)
		return (void *)kernel32::RemoveDirectoryA;
	if (strcmp(name, "SetFileAttributesA") == 0)
		return (void *)kernel32::SetFileAttributesA;
	if (strcmp(name, "GetFileSize") == 0)
		return (void *)kernel32::GetFileSize;
	if (strcmp(name, "GetFileTime") == 0)
		return (void *)kernel32::GetFileTime;
	if (strcmp(name, "SetFileTime") == 0)
		return (void *)kernel32::SetFileTime;
	if (strcmp(name, "GetFileType") == 0)
		return (void *)kernel32::GetFileType;
	if (strcmp(name, "FileTimeToLocalFileTime") == 0)
		return (void *)kernel32::FileTimeToLocalFileTime;
	if (strcmp(name, "LocalFileTimeToFileTime") == 0)
		return (void *)kernel32::LocalFileTimeToFileTime;
	if (strcmp(name, "DosDateTimeToFileTime") == 0)
		return (void *)kernel32::DosDateTimeToFileTime;
	if (strcmp(name, "FileTimeToDosDateTime") == 0)
		return (void *)kernel32::FileTimeToDosDateTime;
	if (strcmp(name, "GetFileInformationByHandle") == 0)
		return (void *)kernel32::GetFileInformationByHandle;
	if (strcmp(name, "GetTempFileNameA") == 0)
		return (void *)kernel32::GetTempFileNameA;
	if (strcmp(name, "GetTempPathA") == 0)
		return (void *)kernel32::GetTempPathA;
	if (strcmp(name, "GetLongPathNameA") == 0)
		return (void *)kernel32::GetLongPathNameA;
	if (strcmp(name, "GetLongPathNameW") == 0)
		return (void *)kernel32::GetLongPathNameW;
	if (strcmp(name, "GetDiskFreeSpaceA") == 0)
		return (void *)kernel32::GetDiskFreeSpaceA;
	if (strcmp(name, "GetDiskFreeSpaceW") == 0)
		return (void *)kernel32::GetDiskFreeSpaceW;
	if (strcmp(name, "GetDiskFreeSpaceExA") == 0)
		return (void *)kernel32::GetDiskFreeSpaceExA;
	if (strcmp(name, "GetDiskFreeSpaceExW") == 0)
		return (void *)kernel32::GetDiskFreeSpaceExW;

	// sysinfoapi.h
	if (strcmp(name, "GetSystemInfo") == 0)
		return (void *)kernel32::GetSystemInfo;
	if (strcmp(name, "GetSystemTime") == 0)
		return (void *)kernel32::GetSystemTime;
	if (strcmp(name, "GetLocalTime") == 0)
		return (void *)kernel32::GetLocalTime;
	if (strcmp(name, "GetSystemTimeAsFileTime") == 0)
		return (void *)kernel32::GetSystemTimeAsFileTime;
	if (strcmp(name, "GetTickCount") == 0)
		return (void *)kernel32::GetTickCount;
	if (strcmp(name, "GetSystemDirectoryA") == 0)
		return (void *)kernel32::GetSystemDirectoryA;
	if (strcmp(name, "GetWindowsDirectoryA") == 0)
		return (void *)kernel32::GetWindowsDirectoryA;
	if (strcmp(name, "GetVersion") == 0)
		return (void *)kernel32::GetVersion;
	if (strcmp(name, "GetVersionExA") == 0)
		return (void *)kernel32::GetVersionExA;

	// timezoneapi.h
	if (strcmp(name, "SystemTimeToFileTime") == 0)
		return (void *)kernel32::SystemTimeToFileTime;
	if (strcmp(name, "FileTimeToSystemTime") == 0)
		return (void *)kernel32::FileTimeToSystemTime;
	if (strcmp(name, "GetTimeZoneInformation") == 0)
		return (void *)kernel32::GetTimeZoneInformation;

	// libloaderapi.h
	if (strcmp(name, "GetModuleHandleA") == 0)
		return (void *)kernel32::GetModuleHandleA;
	if (strcmp(name, "GetModuleHandleW") == 0)
		return (void *)kernel32::GetModuleHandleW;
	if (strcmp(name, "GetModuleFileNameA") == 0)
		return (void *)kernel32::GetModuleFileNameA;
	if (strcmp(name, "GetModuleFileNameW") == 0)
		return (void *)kernel32::GetModuleFileNameW;
	if (strcmp(name, "LoadResource") == 0)
		return (void *)kernel32::LoadResource;
	if (strcmp(name, "LockResource") == 0)
		return (void *)kernel32::LockResource;
	if (strcmp(name, "SizeofResource") == 0)
		return (void *)kernel32::SizeofResource;
	if (strcmp(name, "LoadLibraryA") == 0)
		return (void *)kernel32::LoadLibraryA;
	if (strcmp(name, "LoadLibraryW") == 0)
		return (void *)kernel32::LoadLibraryW;
	if (strcmp(name, "LoadLibraryExW") == 0)
		return (void *)kernel32::LoadLibraryExW;
	if (strcmp(name, "DisableThreadLibraryCalls") == 0)
		return (void *)kernel32::DisableThreadLibraryCalls;
	if (strcmp(name, "FreeLibrary") == 0)
		return (void *)kernel32::FreeLibrary;
	if (strcmp(name, "GetProcAddress") == 0)
		return (void *)kernel32::GetProcAddress;

	// heapapi.h
	if (strcmp(name, "HeapCreate") == 0)
		return (void *)kernel32::HeapCreate;
	if (strcmp(name, "GetProcessHeap") == 0)
		return (void *)kernel32::GetProcessHeap;
	if (strcmp(name, "HeapSetInformation") == 0)
		return (void *)kernel32::HeapSetInformation;
	if (strcmp(name, "HeapAlloc") == 0)
		return (void *)kernel32::HeapAlloc;
	if (strcmp(name, "HeapDestroy") == 0)
		return (void *)kernel32::HeapDestroy;
	if (strcmp(name, "HeapReAlloc") == 0)
		return (void *)kernel32::HeapReAlloc;
	if (strcmp(name, "HeapSize") == 0)
		return (void *)kernel32::HeapSize;
	if (strcmp(name, "HeapFree") == 0)
		return (void *)kernel32::HeapFree;

	// memoryapi.h
	if (strcmp(name, "VirtualAlloc") == 0)
		return (void *)kernel32::VirtualAlloc;
	if (strcmp(name, "VirtualFree") == 0)
		return (void *)kernel32::VirtualFree;
	if (strcmp(name, "VirtualProtect") == 0)
		return (void *)kernel32::VirtualProtect;
	if (strcmp(name, "VirtualQuery") == 0)
		return (void *)kernel32::VirtualQuery;
	if (strcmp(name, "GetProcessWorkingSetSize") == 0)
		return (void *)kernel32::GetProcessWorkingSetSize;
	if (strcmp(name, "SetProcessWorkingSetSize") == 0)
		return (void *)kernel32::SetProcessWorkingSetSize;

	// stringapiset.h
	if (strcmp(name, "WideCharToMultiByte") == 0)
		return (void *)kernel32::WideCharToMultiByte;
	if (strcmp(name, "MultiByteToWideChar") == 0)
		return (void *)kernel32::MultiByteToWideChar;
	if (strcmp(name, "GetStringTypeA") == 0)
		return (void *)kernel32::GetStringTypeA;
	if (strcmp(name, "GetStringTypeW") == 0)
		return (void *)kernel32::GetStringTypeW;

	// profileapi.h
	if (strcmp(name, "QueryPerformanceCounter") == 0)
		return (void *)kernel32::QueryPerformanceCounter;
	if (strcmp(name, "QueryPerformanceFrequency") == 0)
		return (void *)kernel32::QueryPerformanceFrequency;

	// debugapi.h
	if (strcmp(name, "IsDebuggerPresent") == 0)
		return (void *)kernel32::IsDebuggerPresent;

	// errhandlingapi.h
	if (strcmp(name, "SetUnhandledExceptionFilter") == 0)
		return (void *)kernel32::SetUnhandledExceptionFilter;
	if (strcmp(name, "UnhandledExceptionFilter") == 0)
		return (void *)kernel32::UnhandledExceptionFilter;
	if (strcmp(name, "SetErrorMode") == 0)
		return (void *)kernel32::SetErrorMode;

	// interlockedapi.h
	if (strcmp(name, "InitializeSListHead") == 0)
		return (void *)kernel32::InitializeSListHead;

	// winnt.h
	if (strcmp(name, "RtlUnwind") == 0)
		return (void *)kernel32::RtlUnwind;
	if (strcmp(name, "InterlockedIncrement") == 0)
		return (void *)kernel32::InterlockedIncrement;
	if (strcmp(name, "InterlockedDecrement") == 0)
		return (void *)kernel32::InterlockedDecrement;
	if (strcmp(name, "InterlockedExchange") == 0)
		return (void *)kernel32::InterlockedExchange;
	if (strcmp(name, "InterlockedCompareExchange") == 0)
		return (void *)kernel32::InterlockedCompareExchange;

	// fibersapi.h
	if (strcmp(name, "FlsAlloc") == 0)
		return (void *)kernel32::FlsAlloc;
	if (strcmp(name, "FlsFree") == 0)
		return (void *)kernel32::FlsFree;
	if (strcmp(name, "FlsSetValue") == 0)
		return (void *)kernel32::FlsSetValue;
	if (strcmp(name, "FlsGetValue") == 0)
		return (void *)kernel32::FlsGetValue;

	// ioapiset.h
	if (strcmp(name, "GetOverlappedResult") == 0)
		return (void *)kernel32::GetOverlappedResult;

	return 0;
}

wibo::Module lib_kernel32 = {
	(const char *[]){
		"kernel32",
		nullptr,
	},
	resolveByName,
	nullptr,
};
