#include "common.h"
#include "strings.h"
#include <vector>

size_t wstrlen(const uint16_t *str) {
	size_t len = 0;
	while (str[len] != 0)
		++len;
	return len;
}

size_t wstrncpy(uint16_t *dst, const uint16_t *src, size_t n) {
	size_t i = 0;
	while (i < n && src[i] != 0) {
		dst[i] = src[i];
		++i;
	}
	if (i < n)
		dst[i] = 0;
	return i;
}

std::string wideStringToString(const uint16_t *src, int len = -1) {
	if (len < 0) {
		len = src ? wstrlen(src) : 0;
	}
	std::string res(len, '\0');
	for (int i = 0; i < len; i++) {
		res[i] = src[i] & 0xFF;
	}
	return res;
}

std::vector<uint16_t> stringToWideString(const char *src) {
	int len = strlen(src);
	std::vector<uint16_t> res(len + 1);

	for (size_t i = 0; i < res.size(); i++) {
		res[i] = src[i] & 0xFF;
	}
	res[len] = 0; // NUL terminate

	return res;
}