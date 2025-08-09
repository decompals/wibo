#include <string>
#include <vector>

size_t wstrlen(const uint16_t *str);
size_t wstrnlen(const uint16_t* str, size_t numberOfElements);
int wstrncmp(const uint16_t *string1, const uint16_t *string2, size_t count);
const uint16_t* wstrstr(const uint16_t *dest, const uint16_t *src);
uint16_t* wstrrchr(const uint16_t* str, uint16_t c);
uint16_t* wstrcat(uint16_t* dest, const uint16_t* src);
uint16_t* wstrncat(uint16_t* dest, const uint16_t* src, size_t count);
size_t wstrncpy(uint16_t *dst, const uint16_t *src, size_t n);
std::string wideStringToString(const uint16_t *src, int len = -1);
std::vector<uint16_t> stringToWideString(const char *src);
long wstrtol(const uint16_t* string, uint16_t** end_ptr, int base);
unsigned long wstrtoul(const uint16_t* strSource, uint16_t** end_ptr, int base);