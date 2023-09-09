#include <filesystem>
#include <string>

namespace files {
	std::filesystem::path pathFromWindows(const char *inStr);
	std::string pathToWindows(const std::filesystem::path &path);
	void *allocFpHandle(FILE *fp);
	FILE *fpFromHandle(void *handle, bool pop = false);
	void *getStdHandle(uint32_t nStdHandle);
	unsigned int setStdHandle(uint32_t nStdHandle, void *hHandle);
	void init();
}

inline bool endsWith(const std::string &str, const std::string &suffix) {
	return str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}
