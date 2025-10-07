#pragma once

#include "common.h"
#include "kernel32/internal.h"

#include <cstdio>
#include <filesystem>
#include <optional>
#include <string>

using kernel32::FileObject;

namespace files {

struct IOResult {
	size_t bytesTransferred = 0;
	int unixError = 0;
	bool reachedEnd = false;
};

void init();
std::filesystem::path pathFromWindows(const char *inStr);
std::string pathToWindows(const std::filesystem::path &path);
IOResult read(FileObject *file, void *buffer, size_t bytesToRead, const std::optional<off_t> &offset,
			  bool updateFilePointer);
IOResult write(FileObject *file, const void *buffer, size_t bytesToWrite, const std::optional<off_t> &offset,
			   bool updateFilePointer);
HANDLE getStdHandle(DWORD nStdHandle);
BOOL setStdHandle(DWORD nStdHandle, HANDLE hHandle);
std::optional<std::filesystem::path> findCaseInsensitiveFile(const std::filesystem::path &directory,
															 const std::string &filename);
std::filesystem::path canonicalPath(const std::filesystem::path &path);
std::string hostPathListToWindows(const std::string &value);
std::string windowsPathListToHost(const std::string &value);

} // namespace files

inline bool endsWith(const std::string &str, const std::string &suffix) {
	return str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}
