#include "common.h"
#include "context.h"
#include "errors.h"
#include "files.h"
#include "modules.h"
#include "resources.h"
#include "strutil.h"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

namespace {

constexpr uint32_t RT_VERSION = 16;

uint16_t readU16(const uint8_t *ptr) { return static_cast<uint16_t>(ptr[0] | (ptr[1] << 8)); }

size_t align4(size_t offset) { return (offset + 3u) & ~static_cast<size_t>(3u); }

std::string narrowKey(const std::u16string &key) {
	std::string result;
	result.reserve(key.size());
	for (char16_t ch : key) {
		result.push_back(static_cast<char>(ch & 0xFF));
	}
	return result;
}

struct VersionBlockView {
	uint16_t totalLength = 0;
	uint16_t valueLength = 0;
	uint16_t type = 0;
	std::u16string key;
	const uint8_t *valuePtr = nullptr;
	uint32_t valueBytes = 0;
	const uint8_t *childrenPtr = nullptr;
	uint32_t childrenBytes = 0;
};

bool parseVersionBlock(const uint8_t *block, size_t available, VersionBlockView &out) {
	if (available < sizeof(uint16_t) * 3) {
		DEBUG_LOG("header too small: available=%zu\n", available);
		return false;
	}

	uint16_t totalLength = readU16(block);
	uint16_t valueLength = readU16(block + sizeof(uint16_t));
	uint16_t type = readU16(block + sizeof(uint16_t) * 2);
	if (totalLength == 0 || totalLength > available) {
		DEBUG_LOG("invalid totalLength=%u available=%zu\n", totalLength, available);
		return false;
	}

	const uint8_t *end = block + totalLength;
	const uint8_t *cursor = block + sizeof(uint16_t) * 3;
	out.key.clear();
	while (cursor + sizeof(uint16_t) <= end) {
		uint16_t ch = readU16(cursor);
		cursor += sizeof(uint16_t);
		if (!ch)
			break;
		out.key.push_back(static_cast<char16_t>(ch));
	}
	DEBUG_LOG("parsed key fragment=%s\n", narrowKey(out.key).c_str());

	cursor = block + sizeof(uint16_t) * 3 + (out.key.size() + 1) * sizeof(uint16_t);
	if (cursor > end) {
		DEBUG_LOG("key cursor beyond block: cursor=%zu end=%zu\n", static_cast<size_t>(cursor - block),
				  static_cast<size_t>(end - block));
		return false;
	}

	cursor = block + align4(static_cast<size_t>(cursor - block));

	uint32_t valueBytes = 0;
	if (valueLength) {
		valueBytes =
			type == 1 ? static_cast<uint32_t>(valueLength) * sizeof(uint16_t) : static_cast<uint32_t>(valueLength);
		if (cursor + valueBytes > end) {
			DEBUG_LOG("value beyond block: bytes=%u remaining=%zu\n", valueBytes, static_cast<size_t>(end - cursor));
			return false;
		}
	}

	const uint8_t *children = block + align4(static_cast<size_t>((cursor + valueBytes) - block));
	if (children > end)
		children = end;

	out.totalLength = totalLength;
	out.valueLength = valueLength;
	out.type = type;
	out.valuePtr = valueLength ? cursor : nullptr;
	out.valueBytes = valueBytes;
	out.childrenPtr = children;
	out.childrenBytes = static_cast<uint32_t>(end - children);
	return true;
}

bool queryVersionBlock(const uint8_t *block, size_t available, const std::vector<std::string> &segments, size_t depth,
					   const uint8_t **outPtr, uint32_t *outLen, uint16_t *outType) {
	VersionBlockView view;
	if (!parseVersionBlock(block, available, view))
		return false;

	if (depth == segments.size()) {
		if (outPtr)
			*outPtr = view.valueBytes ? view.valuePtr : nullptr;
		if (outLen)
			*outLen = view.type == 1 ? view.valueLength : view.valueBytes;
		if (outType)
			*outType = view.type;
		return true;
	}

	const std::string targetLower = stringToLower(segments[depth]);
	const uint8_t *cursor = view.childrenPtr;
	const uint8_t *end = view.childrenPtr + view.childrenBytes;

	while (cursor + 6 <= end) {
		const uint8_t *childStart = cursor;
		VersionBlockView child;
		if (!parseVersionBlock(cursor, static_cast<size_t>(end - cursor), child))
			break;
		if (child.totalLength == 0)
			break;
		std::string childKeyLower = stringToLower(narrowKey(child.key));
		if (childKeyLower == targetLower) {
			if (queryVersionBlock(childStart, child.totalLength, segments, depth + 1, outPtr, outLen, outType))
				return true;
		}
		const auto offset = static_cast<size_t>(child.totalLength);
		cursor = childStart + align4(offset);
		if (cursor <= childStart || cursor > end)
			break;
	}
	return false;
}

bool splitSubBlock(const std::string &subBlock, std::vector<std::string> &segments) {
	segments.clear();
	if (subBlock.empty() || subBlock == "\\")
		return true;

	const char *cursor = subBlock.c_str();
	if (*cursor == '\\')
		++cursor;

	while (*cursor) {
		const char *next = std::strchr(cursor, '\\');
		if (!next)
			next = cursor + std::strlen(cursor);
		segments.emplace_back(cursor, static_cast<size_t>(next - cursor));
		cursor = *next ? next + 1 : next;
	}
	return true;
}

bool loadVersionResource(const char *fileName, std::vector<uint8_t> &buffer) {
	if (!fileName) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return false;
	}

	auto hostPath = files::pathFromWindows(fileName);
	std::string hostPathStr = hostPath.string();
	FILE *fp = std::fopen(hostPathStr.c_str(), "rb");
	if (!fp) {
		wibo::lastError = ERROR_FILE_NOT_FOUND;
		return false;
	}

	wibo::Executable executable;
	if (!executable.loadPE(fp, false)) {
		std::fclose(fp);
		wibo::lastError = ERROR_BAD_EXE_FORMAT;
		return false;
	}

	std::fclose(fp);

	wibo::ResourceIdentifier type = wibo::ResourceIdentifier::fromID(RT_VERSION);
	wibo::ResourceIdentifier name = wibo::ResourceIdentifier::fromID(1);
	wibo::ResourceLocation loc;
	if (!executable.findResource(type, name, std::nullopt, loc)) {
		auto nameString = wibo::ResourceIdentifier::fromString(u"VS_VERSION_INFO");
		if (!executable.findResource(type, nameString, std::nullopt, loc))
			return false;
	}

	const uint8_t *start = static_cast<const uint8_t *>(loc.data);
	buffer.assign(start, start + loc.size);
	return true;
}

} // namespace

namespace version {

unsigned int WIN_FUNC GetFileVersionInfoSizeA(const char *lptstrFilename, unsigned int *lpdwHandle) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetFileVersionInfoSizeA(%s, %p)\n", lptstrFilename, lpdwHandle);
	if (lpdwHandle)
		*lpdwHandle = 0;

	std::vector<uint8_t> buffer;
	if (!loadVersionResource(lptstrFilename, buffer))
		return 0;
	return static_cast<unsigned int>(buffer.size());
}

unsigned int WIN_FUNC GetFileVersionInfoA(const char *lptstrFilename, unsigned int dwHandle, unsigned int dwLen,
										  void *lpData) {
	HOST_CONTEXT_GUARD();
	(void)dwHandle;
	DEBUG_LOG("GetFileVersionInfoA(%s, %u, %p)\n", lptstrFilename, dwLen, lpData);
	if (!lpData || dwLen == 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return 0;
	}

	std::vector<uint8_t> buffer;
	if (!loadVersionResource(lptstrFilename, buffer))
		return 0;

	if (buffer.size() > dwLen) {
		wibo::lastError = ERROR_INSUFFICIENT_BUFFER;
		return 0;
	}

	std::memcpy(lpData, buffer.data(), buffer.size());
	if (buffer.size() < dwLen) {
		std::memset(static_cast<uint8_t *>(lpData) + buffer.size(), 0, dwLen - buffer.size());
	}
	return 1;
}

static unsigned int VerQueryValueImpl(const void *pBlock, const std::string &subBlock, void **lplpBuffer,
									  unsigned int *puLen) {
	if (!pBlock)
		return 0;

	const auto *base = static_cast<const uint8_t *>(pBlock);
	uint16_t totalLength = readU16(base);
	if (totalLength < 6)
		return 0;

	std::vector<std::string> segments;
	if (!splitSubBlock(subBlock, segments))
		return 0;

	const uint8_t *outPtr = nullptr;
	uint32_t outLen = 0;
	uint16_t outType = 0;
	if (!queryVersionBlock(base, totalLength, segments, 0, &outPtr, &outLen, &outType))
		return 0;

	if (outType == 1 && outPtr) {
		char *dest = reinterpret_cast<char *>(const_cast<uint8_t *>(outPtr));
		std::string narrow = wideStringToString(reinterpret_cast<const uint16_t *>(outPtr), static_cast<int>(outLen));
		std::memcpy(dest, narrow.c_str(), narrow.size() + 1);
		if (lplpBuffer)
			*lplpBuffer = dest;
		if (puLen)
			*puLen = static_cast<unsigned int>(narrow.size());
		return 1;
	}

	if (lplpBuffer)
		*lplpBuffer = const_cast<uint8_t *>(outPtr);
	if (puLen)
		*puLen = outLen;
	return 1;
}

unsigned int WIN_FUNC VerQueryValueA(const void *pBlock, const char *lpSubBlock, void **lplpBuffer,
									 unsigned int *puLen) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("VerQueryValueA(%p, %s, %p, %p)\n", pBlock, lpSubBlock ? lpSubBlock : "(null)", lplpBuffer, puLen);
	if (!lpSubBlock)
		return 0;
	return VerQueryValueImpl(pBlock, lpSubBlock, lplpBuffer, puLen);
}

unsigned int WIN_FUNC GetFileVersionInfoSizeW(const uint16_t *lptstrFilename, unsigned int *lpdwHandle) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetFileVersionInfoSizeW -> ");
	auto narrow = wideStringToString(lptstrFilename);
	return GetFileVersionInfoSizeA(narrow.c_str(), lpdwHandle);
}

unsigned int WIN_FUNC GetFileVersionInfoW(const uint16_t *lptstrFilename, unsigned int dwHandle, unsigned int dwLen,
										  void *lpData) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetFileVersionInfoW -> ");
	auto narrow = wideStringToString(lptstrFilename);
	return GetFileVersionInfoA(narrow.c_str(), dwHandle, dwLen, lpData);
}

unsigned int WIN_FUNC VerQueryValueW(const void *pBlock, const uint16_t *lpSubBlock, void **lplpBuffer,
									 unsigned int *puLen) {
	HOST_CONTEXT_GUARD();
	if (!lpSubBlock)
		return 0;
	auto narrow = wideStringToString(lpSubBlock);
	DEBUG_LOG("VerQueryValueW(%p, %s, %p, %p)\n", pBlock, narrow.c_str(), lplpBuffer, puLen);
	return VerQueryValueImpl(pBlock, narrow, lplpBuffer, puLen);
}

} // namespace version

static void *resolveByName(const char *name) {
	if (strcmp(name, "GetFileVersionInfoSizeA") == 0)
		return (void *)version::GetFileVersionInfoSizeA;
	if (strcmp(name, "GetFileVersionInfoA") == 0)
		return (void *)version::GetFileVersionInfoA;
	if (strcmp(name, "VerQueryValueA") == 0)
		return (void *)version::VerQueryValueA;
	if (strcmp(name, "GetFileVersionInfoSizeW") == 0)
		return (void *)version::GetFileVersionInfoSizeW;
	if (strcmp(name, "GetFileVersionInfoW") == 0)
		return (void *)version::GetFileVersionInfoW;
	if (strcmp(name, "VerQueryValueW") == 0)
		return (void *)version::VerQueryValueW;
	return nullptr;
}

extern const wibo::ModuleStub lib_version = {
	(const char *[]){
		"version",
		nullptr,
	},
	resolveByName,
	nullptr,
};
