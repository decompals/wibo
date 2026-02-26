#include "files.h"
#include "common.h"
#include "errors.h"
#include "handles.h"
#include "strutil.h"

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <mutex>
#include <optional>
#include <string>
#include <strings.h>
#include <map>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>
#include <utility>

kernel32::FsObject::~FsObject() {
	int fd = std::exchange(this->fd, -1);
	if (fd >= 0 && closeOnDestroy) {
		close(fd);
	}
	if (deletePending && !canonicalPath.empty()) {
		if (unlink(canonicalPath.c_str()) != 0) {
			perror("Failed to delete file on close");
		}
	}
}

namespace files {

static std::vector<std::string> splitList(const std::string &value, char delimiter) {
	std::vector<std::string> entries;
	size_t start = 0;
	while (start <= value.size()) {
		size_t end = value.find(delimiter, start);
		if (end == std::string::npos) {
			end = value.size();
		}
		entries.emplace_back(value.substr(start, end - start));
		if (end == value.size()) {
			break;
		}
		start = end + 1;
	}
	return entries;
}

static std::string toWindowsPathEntry(const std::string &entry) {
	if (entry.empty()) {
		return {};
	}
	bool looksWindows =
		entry.find('\\') != std::string::npos || (entry.size() >= 2 && entry[1] == ':' && entry[0] != '/');
	if (looksWindows) {
		std::string normalized = entry;
		std::replace(normalized.begin(), normalized.end(), '/', '\\');
		return normalized;
	}
	return pathToWindows(std::filesystem::path(entry));
}

static std::string toHostPathEntry(const std::string &entry) {
	if (entry.empty()) {
		return {};
	}
	auto converted = pathFromWindows(entry.c_str());
	if (!converted.empty()) {
		return converted.string();
	}
	std::string normalized = entry;
	std::replace(normalized.begin(), normalized.end(), '\\', '/');
	return normalized;
}

static HANDLE stdinHandle;
static HANDLE stdoutHandle;
static HANDLE stderrHandle;

static std::string getDriveMapping(char drive) {
	char envVar[] = "WIBO_DRIVE_X";
	envVar[11] = toupper(drive);
	const char *val = getenv(envVar);
	return val ? val : "";
}

struct PathMapEntry {
	std::string winPath;  // Normalized Windows-style prefix (forward slashes, no trailing slash)
	std::string hostPath; // Host filesystem path
};

// Parse WIBO_PATH_MAP once and cache the result.
// Format: "winPath=hostPath;winPath2=hostPath2;..."
static const std::vector<PathMapEntry> &getPathMap() {
	static std::vector<PathMapEntry> entries;
	static bool parsed = false;
	if (!parsed) {
		parsed = true;
		const char *envVal = getenv("WIBO_PATH_MAP");
		if (envVal) {
			std::string mapStr = envVal;
			size_t start = 0;
			while (start < mapStr.size()) {
				size_t end = mapStr.find(';', start);
				std::string entry = mapStr.substr(start, (end == std::string::npos) ? std::string::npos : end - start);
				size_t sep = entry.find('=');
				if (sep != std::string::npos) {
					std::string winPart = entry.substr(0, sep);
					std::string hostPart = entry.substr(sep + 1);
					std::replace(winPart.begin(), winPart.end(), '\\', '/');
					while (winPart.size() > 1 && winPart.back() == '/')
						winPart.pop_back();
					entries.push_back({std::move(winPart), std::move(hostPart)});
				}
				if (end == std::string::npos)
					break;
				start = end + 1;
			}
		}
	}
	return entries;
}

static std::filesystem::path resolveCaseInsensitive(const std::filesystem::path &path) {
	std::filesystem::path norm = path.lexically_normal();
	if (std::filesystem::exists(norm)) {
		return norm;
	}

	std::filesystem::path newPath = ".";
	if (norm.is_absolute()) {
		newPath = norm.root_path();
	}

	bool followingExisting = true;
	auto it = norm.begin();
	if (norm.is_absolute()) {
		++it;
	}

	for (; it != norm.end(); ++it) {
		const auto &component = *it;
		std::filesystem::path nextPath = newPath / component;
		if (followingExisting && !std::filesystem::exists(nextPath) &&
			(component != ".." && component != "." && component != "")) {
			followingExisting = false;
			std::error_code ec;
			std::filesystem::directory_iterator iter{newPath, ec};
			if (!ec) {
				for (std::filesystem::path entry : iter) {
					if (strcasecmp(entry.filename().c_str(), component.string().c_str()) == 0) {
						followingExisting = true;
						nextPath = entry;
						break;
					}
				}
			}
		}
		newPath = nextPath;
	}

	if (followingExisting) {
		DEBUG_LOG("Resolved case-insensitive path: %s -> %s\n", path.c_str(), newPath.c_str());
		return newPath;
	}
	return norm;
}

static std::filesystem::path applyPathMap(const std::string &inStr) {
	std::string str = inStr;
	std::replace(str.begin(), str.end(), '\\', '/');

	const auto &entries = getPathMap();
	if (entries.empty())
		return {};

	std::string strLower = str;
	toLowerInPlace(strLower);

	for (const auto &e : entries) {
		std::string winLower = e.winPath;
		toLowerInPlace(winLower);

		if (strLower.rfind(winLower, 0) == 0 &&
			(strLower.size() == winLower.size() || strLower[winLower.size()] == '/')) {
			std::string rest = str.substr(e.winPath.size());
			std::filesystem::path hostBase(e.hostPath);
			std::filesystem::path result;
			if (rest.empty() || (rest.size() == 1 && rest[0] == '/')) {
				result = hostBase;
			} else {
				if (rest[0] == '/')
					rest.erase(0, 1);
				result = hostBase / rest;
			}
			return resolveCaseInsensitive(result);
		}
	}
	DEBUG_LOG("applyPathMap: %s -> (no match)\n", str.c_str());
	return {};
}

std::filesystem::path pathFromWindows(const char *inStr) {
	// Try path map first
	std::filesystem::path mapped = applyPathMap(inStr);
	if (!mapped.empty()) {
		return mapped;
	}

	// Normalize to forward slashes
	std::string str = inStr;
	std::replace(str.begin(), str.end(), '\\', '/');

	// Remove "//?/" prefix
	if (str.rfind("//?/", 0) == 0) {
		str.erase(0, 4);
	}

	// Handle drive letter mapping
	if (str.size() >= 2 && str[1] == ':') {
		std::string mapping = getDriveMapping(str[0]);
		if (!mapping.empty()) {
			std::string rest = (str.size() >= 3 && str[2] == '/') ? str.substr(3) : str.substr(2);
			std::filesystem::path p = std::filesystem::path(mapping) / rest;
			return resolveCaseInsensitive(p);
		}
		// Fallback: strip drive letter
		if (str.size() >= 3 && str[2] == '/') {
			str.erase(0, 2);
		}
	}

	return resolveCaseInsensitive(str);
}

std::string pathToWindows(const std::filesystem::path &path) {
	std::string hostStr = std::filesystem::absolute(path).lexically_normal().string();

	// Try path map first (most specific first)
	const auto &entries = getPathMap();
	for (const auto &e : entries) {
		std::string hostPart = std::filesystem::absolute(e.hostPath).lexically_normal().string();
		if (hostStr.rfind(hostPart, 0) == 0) {
			std::string rest = hostStr.substr(hostPart.size());
			if (!rest.empty() && (rest[0] == '/' || rest[0] == '\\'))
				rest.erase(0, 1);
			std::string result = e.winPath;
			if (!result.empty() && result.back() != '\\' && result.back() != '/' && !rest.empty())
				result += '\\';
			result += rest;
			std::replace(result.begin(), result.end(), '/', '\\');
			return result;
		}
	}

	std::string str = path.lexically_normal().string();

	// Check for mapped drives
	for (char d = 'A'; d <= 'Z'; ++d) {
		std::string mapping = getDriveMapping(d);
		if (mapping.empty())
			continue;
		std::string mappingNorm = std::filesystem::path(mapping).lexically_normal().string();
		if (str.rfind(mappingNorm, 0) == 0) {
			std::string drivePrefix = "X:";
			drivePrefix[0] = d;
			str.replace(0, mappingNorm.size(), drivePrefix);
			std::replace(str.begin(), str.end(), '/', '\\');
			return str;
		}
	}

	if (path.is_absolute()) {
		str.insert(0, "Z:");
	}

	std::replace(str.begin(), str.end(), '/', '\\');
	return str;
}

IOResult read(FileObject *file, void *buffer, size_t bytesToRead, const std::optional<off_t> &offset,
			  bool updateFilePointer) {
	IOResult result{};
	if (!file || !file->valid()) {
		result.unixError = EBADF;
		return result;
	}
	if (bytesToRead == 0) {
		return result;
	}

	// Sanity check: if no offset is given, we must update the file pointer
	assert(offset.has_value() || updateFilePointer);

	if (file->isPipe) {
		std::lock_guard lk(file->m);
		size_t chunk = bytesToRead > SSIZE_MAX ? SSIZE_MAX : bytesToRead;
		uint8_t *in = static_cast<uint8_t *>(buffer);
		ssize_t rc;
		while (true) {
			rc = ::read(file->fd, in, chunk);
			if (rc == -1 && errno == EINTR) {
				continue;
			}
			break;
		}
		if (rc == -1) {
			result.unixError = errno ? errno : EIO;
			return result;
		}
		if (rc == 0) {
			result.reachedEnd = true;
			return result;
		}
		result.bytesTransferred = static_cast<size_t>(rc);
		return result;
	}

	const auto doRead = [&](off_t pos) {
		size_t total = 0;
		size_t remaining = bytesToRead;
		uint8_t *in = static_cast<uint8_t *>(buffer);
		while (remaining > 0) {
			size_t chunk = remaining > SSIZE_MAX ? SSIZE_MAX : remaining;
			ssize_t rc = pread(file->fd, in + total, chunk, pos);
			if (rc == -1) {
				if (errno == EINTR) {
					continue;
				}
				result.unixError = errno ? errno : EIO;
				break;
			}
			if (rc == 0) {
				result.reachedEnd = true;
				break;
			}
			total += static_cast<size_t>(rc);
			remaining -= static_cast<size_t>(rc);
			pos += rc;
		}
		result.bytesTransferred = total;
	};

	if (updateFilePointer || !offset.has_value()) {
		std::lock_guard lk(file->m);
		const off_t pos = offset.value_or(file->filePos);
		doRead(pos);
		if (updateFilePointer) {
			file->filePos = pos + static_cast<off_t>(result.bytesTransferred);
		}
	} else {
		doRead(*offset);
	}

	return result;
}

IOResult write(FileObject *file, const void *buffer, size_t bytesToWrite, const std::optional<off_t> &offset,
			   bool updateFilePointer) {
	IOResult result{};
	if (!file || !file->valid()) {
		result.unixError = EBADF;
		return result;
	}
	if (bytesToWrite == 0) {
		return result;
	}

	// Sanity check: if no offset is given, we must update the file pointer
	assert(offset.has_value() || updateFilePointer);

	if (file->appendOnly || file->isPipe) {
		std::lock_guard lk(file->m);
		size_t total = 0;
		size_t remaining = bytesToWrite;
		const uint8_t *in = static_cast<const uint8_t *>(buffer);
		while (remaining > 0) {
			size_t chunk = remaining > SSIZE_MAX ? SSIZE_MAX : remaining;
			ssize_t rc = ::write(file->fd, in + total, chunk);
			if (rc == -1) {
				if (errno == EINTR) {
					continue;
				}
				result.unixError = errno ? errno : EIO;
				break;
			}
			if (rc == 0) {
				break;
			}
			total += static_cast<size_t>(rc);
			remaining -= static_cast<size_t>(rc);
		}
		result.bytesTransferred = total;
		if (updateFilePointer) {
			off_t pos = file->isPipe ? 0 : lseek(file->fd, 0, SEEK_CUR);
			if (pos >= 0) {
				file->filePos = pos;
			} else if (result.unixError == 0) {
				result.unixError = errno ? errno : EIO;
			}
		}
		return result;
	}

	auto doWrite = [&](off_t pos) {
		size_t total = 0;
		size_t remaining = bytesToWrite;
		const uint8_t *in = static_cast<const uint8_t *>(buffer);
		while (remaining > 0) {
			size_t chunk = remaining > SSIZE_MAX ? SSIZE_MAX : remaining;
			ssize_t rc = pwrite(file->fd, in + total, chunk, pos);
			if (rc == -1) {
				if (errno == EINTR) {
					continue;
				}
				result.unixError = errno ? errno : EIO;
				break;
			}
			if (rc == 0) {
				break;
			}
			total += static_cast<size_t>(rc);
			remaining -= static_cast<size_t>(rc);
			pos += rc;
		}
		result.bytesTransferred = total;
	};

	if (updateFilePointer || !offset.has_value()) {
		std::lock_guard lk(file->m);
		const off_t pos = offset.value_or(file->filePos);
		doWrite(pos);
		if (updateFilePointer) {
			file->filePos = pos + static_cast<off_t>(result.bytesTransferred);
		}
	} else {
		doWrite(*offset);
	}

	return result;
}

HANDLE getStdHandle(DWORD nStdHandle) {
	switch (nStdHandle) {
	case STD_INPUT_HANDLE:
		return stdinHandle;
	case STD_OUTPUT_HANDLE:
		return stdoutHandle;
	case STD_ERROR_HANDLE:
		return stderrHandle;
	default:
		return INVALID_HANDLE_VALUE;
	}
}

BOOL setStdHandle(DWORD nStdHandle, HANDLE hHandle) {
	switch (nStdHandle) {
	case STD_INPUT_HANDLE:
		stdinHandle = hHandle;
		break;
	case STD_OUTPUT_HANDLE:
		stdoutHandle = hHandle;
		break;
	case STD_ERROR_HANDLE:
		stderrHandle = hHandle;
		break;
	default:
		return 0; // fail
	}
	return 1; // success
}

void init() {
	signal(SIGPIPE, SIG_IGN);
	auto &handles = wibo::handles();
	auto stdinObject = make_pin<FileObject>(STDIN_FILENO);
	stdinObject->closeOnDestroy = false;
	stdinHandle = handles.alloc(std::move(stdinObject), FILE_GENERIC_READ, 0);
	auto stdoutObject = make_pin<FileObject>(STDOUT_FILENO);
	stdoutObject->closeOnDestroy = false;
	stdoutObject->appendOnly = true;
	stdoutHandle = handles.alloc(std::move(stdoutObject), FILE_GENERIC_WRITE, 0);
	auto stderrObject = make_pin<FileObject>(STDERR_FILENO);
	stderrObject->closeOnDestroy = false;
	stderrObject->appendOnly = true;
	stderrHandle = handles.alloc(std::move(stderrObject), FILE_GENERIC_WRITE, 0);
}

std::optional<std::filesystem::path> findCaseInsensitiveFile(const std::filesystem::path &directory,
															 const std::string &filename) {
	std::error_code ec;
	if (directory.empty()) {
		return std::nullopt;
	}
	if (!std::filesystem::exists(directory, ec) || !std::filesystem::is_directory(directory, ec)) {
		return std::nullopt;
	}
	std::string needle = filename;
	toLowerInPlace(needle);
	for (const auto &entry : std::filesystem::directory_iterator(directory, ec)) {
		if (ec) {
			break;
		}
		std::string candidate = entry.path().filename().string();
		toLowerInPlace(candidate);
		if (candidate == needle) {
			return canonicalPath(entry.path());
		}
	}
	auto direct = directory / filename;
	if (std::filesystem::exists(direct, ec)) {
		return canonicalPath(direct);
	}
	return std::nullopt;
}

std::filesystem::path canonicalPath(const std::filesystem::path &path) {
	std::error_code ec;
	auto canonical = std::filesystem::weakly_canonical(path, ec);
	if (!ec) {
		return canonical;
	}
	return std::filesystem::absolute(path);
}

std::string hostPathListToWindows(const std::string &value) {
	if (value.empty()) {
		return value;
	}
	char delimiter = value.find(';') != std::string::npos ? ';' : ':';
	auto entries = splitList(value, delimiter);
	std::string result;
	for (size_t i = 0; i < entries.size(); ++i) {
		if (i != 0) {
			result.push_back(';');
		}
		if (!entries[i].empty()) {
			result += toWindowsPathEntry(entries[i]);
		}
	}
	return result;
}

std::string windowsPathListToHost(const std::string &value) {
	if (value.empty()) {
		return value;
	}
	auto entries = splitList(value, ';');
	std::string result;
	for (size_t i = 0; i < entries.size(); ++i) {
		if (i != 0) {
			result.push_back(':');
		}
		if (!entries[i].empty()) {
			result += toHostPathEntry(entries[i]);
		}
	}
	return result;
}
static std::mutex gMappedFileMutex;
static std::map<std::pair<dev_t, ino_t>, int> gMappedFileCount;

void trackMappedFile(dev_t dev, ino_t ino) {
	std::lock_guard lk(gMappedFileMutex);
	int count = ++gMappedFileCount[{dev, ino}];
	DEBUG_LOG("trackMappedFile: dev=%lu ino=%lu count=%d\n",
		(unsigned long)dev, (unsigned long)ino, count);
}

void untrackMappedFile(dev_t dev, ino_t ino) {
	std::lock_guard lk(gMappedFileMutex);
	auto it = gMappedFileCount.find({dev, ino});
	if (it != gMappedFileCount.end()) {
		if (--it->second <= 0) {
			DEBUG_LOG("untrackMappedFile: dev=%lu ino=%lu (removed)\n",
				(unsigned long)dev, (unsigned long)ino);
			gMappedFileCount.erase(it);
		} else {
			DEBUG_LOG("untrackMappedFile: dev=%lu ino=%lu count=%d\n",
				(unsigned long)dev, (unsigned long)ino, it->second);
		}
	}
}

bool isFileMapped(int fd) {
	struct stat st {};
	if (fstat(fd, &st) != 0) {
		DEBUG_LOG("isFileMapped: fstat failed for fd=%d\n", fd);
		return false;
	}
	std::lock_guard lk(gMappedFileMutex);
	bool mapped = gMappedFileCount.count({st.st_dev, st.st_ino}) > 0;
	DEBUG_LOG("isFileMapped: fd=%d dev=%lu ino=%lu -> %s\n",
		fd, (unsigned long)st.st_dev, (unsigned long)st.st_ino,
		mapped ? "YES (skip truncation)" : "no");
	return mapped;
}

} // namespace files
