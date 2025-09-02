#include "common.h"
#include "strings.h"
#include <cstdint>
#include <vector>
#include <string>
#include <locale>
#include <codecvt>
#include <sstream>

size_t wstrlen(const uint16_t *str) {
	if(!str) return 0;
	
	size_t len = 0;
	while (str[len] != 0)
		++len;
	return len;
}

size_t wstrnlen(const uint16_t* str, size_t numberOfElements){
	size_t len = 0;
    while (str[len] != 0 && len < numberOfElements)
		++len;
    return len;
}

int wstrncmp(const uint16_t *string1, const uint16_t *string2, size_t count){
	const uint16_t* ptr1 = string1;
	const uint16_t* ptr2 = string2;
	for(size_t i = 0; i < count; i++){
		uint16_t c1 = *ptr1++;
		uint16_t c2 = *ptr2++;
		if (c1 != c2) {
            return (c1 > c2) ? 1 : -1;
        }
	}
	return 0;
}

const uint16_t* wstrstr(const uint16_t *dest, const uint16_t *src){
	if (!*src) return dest;

    for (; *dest != 0; dest++) {
        const uint16_t* d = dest;
        const uint16_t* s = src;

        while (*d != 0 && *s != 0 && *d == *s) {
            d++;
            s++;
        }

        if (*s == 0) {
            return dest;
        }
    }

    return nullptr;
}

uint16_t* wstrchr(const uint16_t* str, uint16_t c) {
    for (; *str != 0; str++) {
        if (*str == c) {
            return (uint16_t*)str;
        }
    }
    // If searching for '\0', return pointer to terminator
    if (c == 0) {
        return (uint16_t*)str;
    }
    return nullptr;
}

uint16_t* wstrrchr(const uint16_t* str, uint16_t c){
	const uint16_t* last = nullptr;
    for (; *str != 0; str++) {
        if (*str == c) {
            last = str;
        }
    }
    return (uint16_t*)last;
}

uint16_t* wstrcat(uint16_t* dest, const uint16_t* src){
	uint16_t* d = dest;
	while (*d) d++;
	while ((*d++ = *src++) != 0);
	return dest;
}

uint16_t* wstrncat(uint16_t* dest, const uint16_t* src, size_t count){
    uint16_t* d = dest;
	while (*d) d++;
	for(size_t i = 0; i < count && src[i] != 0; i++){
		*d++ = src[i];
	}
	*d = 0;
    return dest;
}

uint16_t* wstrcpy(uint16_t* dest, const uint16_t* src){
	uint16_t* d = dest;
    while ((*d++ = *src++) != 0);
    return dest;
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
	if(!src) return std::string();
	if (len < 0) {
		len = src ? wstrlen(src) : 0;
	}

	// std::u16string u16str;
	// for(const uint16_t* p = src; *p != 0; p++){
	// 	u16str.push_back(*p);
	// }

	// std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert;
	// return convert.to_bytes(reinterpret_cast<const char16_t*>(u16str.data()));

	// the old implementation
	std::string res(len, '\0');
	std::string debug_wstr;
		std::stringstream ss;
		bool is_wide = false;
	for (int i = 0; i < len; i++) {
		ss << "0x" << std::hex << src[i] << " ";
		// debug_wstr += std::format("0x%X ", src[i]);
		if(src[i] > 255){
		// 	DEBUG_LOG("Encountered wide char with value 0x%X!\n", src[i]);
		// 	assert(src[i] <= 255);
			is_wide = true;
		}
		res[i] = src[i] & 0xFF;
	}
	if(is_wide){
		debug_wstr += ss.str();
		DEBUG_LOG("wideString (%d): %s\n", wstrlen(src), debug_wstr.c_str());
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

long wstrtol(const uint16_t* string, uint16_t** end_ptr, int base){
	if(!string){
		if(end_ptr) *end_ptr = nullptr;
		return 0;
	}

	std::string normal_str = wideStringToString(string);
	char* normal_end = nullptr;
	long res = std::strtol(normal_str.c_str(), &normal_end, base);

	if(end_ptr){
		if(normal_end && *normal_end){
			size_t offset = normal_end - normal_str.c_str();
			*end_ptr = (uint16_t*)(string + offset);
		}
		else {
			*end_ptr = (uint16_t*)(string + normal_str.size());
		}
	}

	return res;
}

unsigned long wstrtoul(const uint16_t* string, uint16_t** end_ptr, int base){
	if(!string){
		if(end_ptr) *end_ptr = nullptr;
		return 0;
	}

	std::string normal_str = wideStringToString(string);
	char* normal_end = nullptr;
	unsigned long res = std::strtoul(normal_str.c_str(), &normal_end, base);

	if(end_ptr){
		if(normal_end && *normal_end){
			size_t offset = normal_end - normal_str.c_str();
			*end_ptr = (uint16_t*)(string + offset);
		}
		else {
			*end_ptr = (uint16_t*)(string + normal_str.size());
		}
	}

	return res;
}