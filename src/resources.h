#pragma once

#include <cstdint>
#include <string>

namespace wibo {

struct Executable;

struct ResourceIdentifier {
	ResourceIdentifier() : isString(false), id(0) {}
	static ResourceIdentifier fromID(uint32_t value) {
		ResourceIdentifier ident;
		ident.isString = false;
		ident.id = value;
		return ident;
	}
	static ResourceIdentifier fromString(std::u16string value) {
		ResourceIdentifier ident;
		ident.isString = true;
		ident.name = std::move(value);
		return ident;
	}
	bool isString;
	uint32_t id;
	std::u16string name;
};

struct ResourceLocation {
	const void *dataEntry = nullptr;
	const void *data = nullptr;
	uint32_t size = 0;
	uint16_t language = 0;
};

struct ImageResourceDataEntry {
	uint32_t offsetToData;
	uint32_t size;
	uint32_t codePage;
	uint32_t reserved;
};

bool resourceEntryBelongsToExecutable(const Executable &exe, const ImageResourceDataEntry *entry);
ResourceIdentifier resourceIdentifierFromAnsi(const char *id);
ResourceIdentifier resourceIdentifierFromWide(const uint16_t *id);

} // namespace wibo
