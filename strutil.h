#include <string>
#include <vector>

size_t wstrlen(const uint16_t *str);
size_t wstrncpy(uint16_t *dst, const uint16_t *src, size_t n);
std::string wideStringToString(const uint16_t *src, int len = -1);
std::vector<uint16_t> stringToWideString(const char *src);