#include "files.h"
#include "common.h"
#include "handles.h"
#include "strutil.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdio>
#include <mutex>
#include <optional>
#include <string>
#include <strings.h>
#include <system_error>
#include <unistd.h>
#include <utility>

kernel32::FsObject::~FsObject() {
	std::lock_guard lk(m);
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

std::filesystem::path pathFromWindows(const char *inStr) {
	// Convert to forward slashes
	std::string str = inStr;
	std::replace(str.begin(), str.end(), '\\', '/');

	// Remove "//?/" prefix
	if (str.rfind("//?/", 0) == 0) {
		str.erase(0, 4);
	}

	// Remove the drive letter
	if (str.rfind("z:/", 0) == 0 || str.rfind("Z:/", 0) == 0 || str.rfind("c:/", 0) == 0 || str.rfind("C:/", 0) == 0) {
		str.erase(0, 2);
	}

	// Return as-is if it exists, else traverse the filesystem looking for
	// a path that matches case insensitively
	std::filesystem::path path = std::filesystem::path(str).lexically_normal();
	if (std::filesystem::exists(path)) {
		return path;
	}

	std::filesystem::path newPath = ".";
	bool followingExisting = true;
	for (const auto &component : path) {
		std::filesystem::path newPath2 = newPath / component;
		if (followingExisting && !std::filesystem::exists(newPath2) &&
			(component != ".." && component != "." && component != "")) {
			followingExisting = false;
			try {
				for (std::filesystem::path entry : std::filesystem::directory_iterator{newPath}) {
					if (strcasecmp(entry.filename().c_str(), component.c_str()) == 0) {
						followingExisting = true;
						newPath2 = entry;
						break;
					}
				}
			} catch (const std::filesystem::filesystem_error &) {
				// not a directory
			}
		}
		newPath = newPath2;
	}
	if (followingExisting) {
		DEBUG_LOG("Resolved case-insensitive path: %s\n", newPath.c_str());
	} else {
		DEBUG_LOG("Failed to resolve path: %s\n", newPath.c_str());
	}

	return newPath;
}

std::string pathToWindows(const std::filesystem::path &path) {
	std::string str = path.lexically_normal();

	if (path.is_absolute()) {
		str.insert(0, "Z:");
	}

	std::replace(str.begin(), str.end(), '/', '\\');
	return str;
}

IOResult read(FileObject *file, void *buffer, size_t bytesToRead, const std::optional<off64_t> &offset,
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

	const auto doRead = [&](off64_t pos) {
		size_t total = 0;
		size_t remaining = bytesToRead;
		uint8_t *in = static_cast<uint8_t *>(buffer);
		while (remaining > 0) {
			size_t chunk = remaining > SSIZE_MAX ? SSIZE_MAX : remaining;
			ssize_t rc = pread64(file->fd, in + total, chunk, pos);
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
		const off64_t pos = offset.value_or(file->filePos);
		doRead(pos);
		if (updateFilePointer) {
			file->filePos = pos + static_cast<off64_t>(result.bytesTransferred);
		}
	} else {
		doRead(*offset);
	}

	return result;
}

IOResult write(FileObject *file, const void *buffer, size_t bytesToWrite, const std::optional<off64_t> &offset,
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
			off64_t pos = file->isPipe ? 0 : lseek64(file->fd, 0, SEEK_CUR);
			if (pos >= 0) {
				file->filePos = pos;
			} else if (result.unixError == 0) {
				result.unixError = errno ? errno : EIO;
			}
		}
		return result;
	}

	auto doWrite = [&](off64_t pos) {
		size_t total = 0;
		size_t remaining = bytesToWrite;
		const uint8_t *in = static_cast<const uint8_t *>(buffer);
		while (remaining > 0) {
			size_t chunk = remaining > SSIZE_MAX ? SSIZE_MAX : remaining;
			ssize_t rc = pwrite64(file->fd, in + total, chunk, pos);
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
		const off64_t pos = offset.value_or(file->filePos);
		doWrite(pos);
		if (updateFilePointer) {
			file->filePos = pos + static_cast<off64_t>(result.bytesTransferred);
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
		return (void *)0xFFFFFFFF;
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
	auto &handles = wibo::handles();
	auto stdinObject = make_pin<FileObject>(STDIN_FILENO);
	stdinObject->closeOnDestroy = false;
	stdinHandle = handles.alloc(std::move(stdinObject), FILE_GENERIC_READ, 0);
	auto stdoutObject = make_pin<FileObject>(STDOUT_FILENO);
	stdoutObject->closeOnDestroy = false;
	stdoutHandle = handles.alloc(std::move(stdoutObject), FILE_GENERIC_WRITE, 0);
	auto stderrObject = make_pin<FileObject>(STDERR_FILENO);
	stderrObject->closeOnDestroy = false;
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
} // namespace files
