#include "filesystem.hpp"

namespace files {
	std::filesystem::path pathFromWindows(const char *inStr);
	std::string pathToWindows(const std::filesystem::path &path);
	void *allocFpHandle(FILE *fp);
	FILE *fpFromHandle(void *handle, bool pop = false);
	void *getStdHandle(uint32_t nStdHandle);
	unsigned int setStdHandle(uint32_t nStdHandle, void *hHandle);
	void init();
}
