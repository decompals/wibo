#pragma once

#include "common.h"
#include "handles.h"

#include <cstdio>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>

namespace files {
	struct FileObject : ObjectHeader {
		int host_fd = -1;		 // use pread/pwrite
		std::mutex pos_mu;		 // sync for file_pos w/o overlapped
		off64_t file_pos = 0;	 // shared across duplicated handles
		bool overlapped = false; // set from FILE_FLAG_OVERLAPPED

		explicit FileObject(int fd, bool ov)
			: ObjectHeader(ObjectType::File), host_fd(fd), overlapped(ov) {}
		virtual ~FileObject() {
			if (host_fd != -1) {
				close(host_fd);
				host_fd = -1;
			}
		}

		[[nodiscard]] bool valid() const { return host_fd >= 0; }
	};

	struct IOResult {
		size_t bytesTransferred = 0;
		int unixError = 0;
		bool reachedEnd = false;
	};

	std::filesystem::path pathFromWindows(const char *inStr);
	std::string pathToWindows(const std::filesystem::path &path);
	void *allocFpHandle(FILE *fp, unsigned int desiredAccess = 0, unsigned int shareMode = 0, unsigned int flags = 0, bool closeOnDestroy = true);
	// void *duplicateFileHandle(FileHandle *handle, bool closeOnDestroy);
	FILE *fpFromHandle(void *handle, bool pop = false);
	// FileHandle *fileHandleFromHandle(void *handle);
	IOResult read(FileObject *handle, void *buffer, size_t bytesToRead, const std::optional<uint64_t> &offset, bool updateFilePointer);
	IOResult write(FileObject *handle, const void *buffer, size_t bytesToWrite, const std::optional<uint64_t> &offset, bool updateFilePointer);
	HANDLE getStdHandle(DWORD nStdHandle);
	BOOL setStdHandle(DWORD nStdHandle, HANDLE hHandle);
	void init();
	std::optional<std::filesystem::path> findCaseInsensitiveFile(const std::filesystem::path &directory, const std::string &filename);
	std::filesystem::path canonicalPath(const std::filesystem::path &path);
	std::string hostPathListToWindows(const std::string &value);
	std::string windowsPathListToHost(const std::string &value);
	} // namespace files

inline bool endsWith(const std::string &str, const std::string &suffix) {
	return str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}
