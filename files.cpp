#include "common.h"
#include "files.h"
#include "handles.h"
#include "strutil.h"
#include <algorithm>
#include <cerrno>
#include <map>
#include <optional>
#include <strings.h>
#include <string>

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
			return std::string();
		}
		bool looksWindows = entry.find('\\') != std::string::npos ||
					(entry.size() >= 2 && entry[1] == ':' && entry[0] != '/');
		if (looksWindows) {
			std::string normalized = entry;
			std::replace(normalized.begin(), normalized.end(), '/', '\\');
			return normalized;
		}
		return pathToWindows(std::filesystem::path(entry));
	}

	static std::string toHostPathEntry(const std::string &entry) {
		if (entry.empty()) {
			return std::string();
		}
		auto converted = pathFromWindows(entry.c_str());
		if (!converted.empty()) {
			return converted.string();
		}
		std::string normalized = entry;
		std::replace(normalized.begin(), normalized.end(), '\\', '/');
		return normalized;
	}

	static void *stdinHandle;
	static void *stdoutHandle;
	static void *stderrHandle;

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
		for (const auto& component : path) {
			std::filesystem::path newPath2 = newPath / component;
			if (followingExisting && !std::filesystem::exists(newPath2) && (component != ".." && component != "." && component != "")) {
				followingExisting = false;
				try {
					for (std::filesystem::path entry : std::filesystem::directory_iterator{newPath}) {
						if (strcasecmp(entry.filename().c_str(), component.c_str()) == 0) {
							followingExisting = true;
							newPath2 = entry;
							break;
						}
					}
				} catch (const std::filesystem::filesystem_error&) {
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

	FileHandle *fileHandleFromHandle(void *handle) {
		handles::Data data = handles::dataFromHandle(handle, false);
		if (data.type == handles::TYPE_FILE) {
			return reinterpret_cast<FileHandle *>(data.ptr);
		}
		return nullptr;
	}

	FILE *fpFromHandle(void *handle, bool pop) {
		handles::Data data = handles::dataFromHandle(handle, pop);
		if (data.type == handles::TYPE_FILE) {
			return reinterpret_cast<FileHandle *>(data.ptr)->fp;
		}
		return nullptr;
	}

	void *allocFpHandle(FILE *fp, unsigned int desiredAccess, unsigned int shareMode, unsigned int flags, bool closeOnDestroy) {
		auto *handle = new FileHandle();
		handle->fp = fp;
		handle->fd = (fp ? fileno(fp) : -1);
		handle->desiredAccess = desiredAccess;
		handle->shareMode = shareMode;
		handle->flags = flags;
		handle->closeOnDestroy = closeOnDestroy;
		return handles::allocDataHandle({handles::TYPE_FILE, handle, 0});
	}

	void *duplicateFileHandle(FileHandle *source, bool closeOnDestroy) {
		if (!source) {
			return nullptr;
		}
		auto *clone = new FileHandle();
		clone->fp = source->fp;
		clone->fd = source->fd;
		clone->desiredAccess = source->desiredAccess;
		clone->shareMode = source->shareMode;
		clone->flags = source->flags;
		clone->closeOnDestroy = closeOnDestroy;
		return handles::allocDataHandle({handles::TYPE_FILE, clone, 0});
	}

	IOResult read(FileHandle *handle, void *buffer, size_t bytesToRead, const std::optional<uint64_t> &offset, bool updateFilePointer) {
		IOResult result{};
		if (!handle || !handle->fp) {
			result.unixError = EBADF;
			return result;
		}
		if (bytesToRead == 0) {
			return result;
		}

		bool useOffset = offset.has_value();
		if (useOffset && !updateFilePointer && handle->fd >= 0) {
			size_t total = 0;
			size_t remaining = bytesToRead;
			off_t pos = static_cast<off_t>(*offset);
			while (remaining > 0) {
				ssize_t rc = pread(handle->fd, static_cast<uint8_t *>(buffer) + total, remaining, pos);
				if (rc == -1) {
					if (errno == EINTR) {
						continue;
					}
					result.bytesTransferred = total;
					result.unixError = errno ? errno : EIO;
					return result;
				}
				if (rc == 0) {
					result.bytesTransferred = total;
					result.reachedEnd = true;
					return result;
				}
				total += static_cast<size_t>(rc);
				remaining -= static_cast<size_t>(rc);
				pos += rc;
			}
			result.bytesTransferred = total;
			return result;
		}

		off_t originalPos = -1;
		std::unique_lock<std::mutex> lock(handle->mutex);
		if (useOffset) {
			originalPos = ftello(handle->fp);
			if (!updateFilePointer && originalPos == -1) {
				result.unixError = errno ? errno : ESPIPE;
				return result;
			}
			if (fseeko(handle->fp, static_cast<off_t>(*offset), SEEK_SET) != 0) {
				result.unixError = errno ? errno : EINVAL;
				return result;
			}
		}

		size_t readCount = fread(buffer, 1, bytesToRead, handle->fp);
		result.bytesTransferred = readCount;
		if (readCount < bytesToRead) {
			if (feof(handle->fp)) {
				result.reachedEnd = true;
				clearerr(handle->fp);
			} else if (ferror(handle->fp)) {
				result.unixError = errno ? errno : EIO;
				clearerr(handle->fp);
			}
		}

		if (useOffset && !updateFilePointer) {
			if (originalPos != -1) {
				fseeko(handle->fp, originalPos, SEEK_SET);
			}
		}
		return result;
	}

	IOResult write(FileHandle *handle, const void *buffer, size_t bytesToWrite, const std::optional<uint64_t> &offset, bool updateFilePointer) {
		IOResult result{};
		if (!handle || !handle->fp) {
			result.unixError = EBADF;
			return result;
		}
		if (bytesToWrite == 0) {
			return result;
		}

		bool useOffset = offset.has_value();
		if (useOffset && !updateFilePointer && handle->fd >= 0) {
			size_t total = 0;
			size_t remaining = bytesToWrite;
			off_t pos = static_cast<off_t>(*offset);
			while (remaining > 0) {
				ssize_t rc = pwrite(handle->fd, static_cast<const uint8_t *>(buffer) + total, remaining, pos);
				if (rc == -1) {
					if (errno == EINTR) {
						continue;
					}
					result.bytesTransferred = total;
					result.unixError = errno ? errno : EIO;
					return result;
				}
				total += static_cast<size_t>(rc);
				remaining -= static_cast<size_t>(rc);
				pos += rc;
			}
			result.bytesTransferred = total;
			return result;
		}

		off_t originalPos = -1;
		std::unique_lock<std::mutex> lock(handle->mutex);
		if (useOffset) {
			originalPos = ftello(handle->fp);
			if (!updateFilePointer && originalPos == -1) {
				result.unixError = errno ? errno : ESPIPE;
				return result;
			}
			if (fseeko(handle->fp, static_cast<off_t>(*offset), SEEK_SET) != 0) {
				result.unixError = errno ? errno : EINVAL;
				return result;
			}
		}

		size_t writeCount = fwrite(buffer, 1, bytesToWrite, handle->fp);
		result.bytesTransferred = writeCount;
		if (writeCount < bytesToWrite) {
			result.unixError = errno ? errno : EIO;
			clearerr(handle->fp);
		}

		if (useOffset && !updateFilePointer) {
			if (originalPos != -1) {
				fseeko(handle->fp, originalPos, SEEK_SET);
			}
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
		stdinHandle = allocFpHandle(stdin, 0, 0, 0, false);
		stdoutHandle = allocFpHandle(stdout, 0, 0, 0, false);
		stderrHandle = allocFpHandle(stderr, 0, 0, 0, false);
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
}
