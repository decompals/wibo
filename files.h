#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace files {
	std::filesystem::path pathFromWindows(const char *inStr);
	std::string pathToWindows(const std::filesystem::path &path);
	void *allocFpHandle(FILE *fp);
	FILE *fpFromHandle(void *handle, bool pop = false);
	void *getStdHandle(uint32_t nStdHandle);
	unsigned int setStdHandle(uint32_t nStdHandle, void *hHandle);
	void init();
	std::optional<std::filesystem::path> findCaseInsensitiveFile(const std::filesystem::path &directory, const std::string &filename);
	std::filesystem::path canonicalPath(const std::filesystem::path &path);
	std::string hostPathListToWindows(const std::string &value);
	std::string windowsPathListToHost(const std::string &value);
}

inline bool endsWith(const std::string &str, const std::string &suffix) {
	return str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}
