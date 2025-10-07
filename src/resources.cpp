#include "resources.h"

#include "common.h"
#include "errors.h"
#include "modules.h"

namespace {

struct ImageResourceDirectory {
	uint32_t characteristics;
	uint32_t timeDateStamp;
	uint16_t majorVersion;
	uint16_t minorVersion;
	uint16_t numberOfNamedEntries;
	uint16_t numberOfIdEntries;
};

struct ImageResourceDirectoryEntry {
	uint32_t name;
	uint32_t offsetToData;
};

constexpr uint32_t RESOURCE_NAME_IS_STRING = 0x80000000u;
constexpr uint32_t RESOURCE_DATA_IS_DIRECTORY = 0x80000000u;

const ImageResourceDirectoryEntry *resourceEntries(const ImageResourceDirectory *dir) {
	return reinterpret_cast<const ImageResourceDirectoryEntry *>(dir + 1);
}

bool resourceOffsetInRange(uint32_t offset, size_t needed, uint32_t available) {
	if (available == 0)
		return true;
	if (offset > available)
		return false;
	if (available - offset < needed)
		return false;
	return true;
}

bool resourceNameEquals(const uint8_t *base, uint32_t nameField, const std::u16string &value, uint32_t rsrcSize) {
	if (!(nameField & RESOURCE_NAME_IS_STRING))
		return false;
	uint32_t offset = nameField & ~RESOURCE_NAME_IS_STRING;
	if (!resourceOffsetInRange(offset, sizeof(uint16_t), rsrcSize))
		return false;
	const auto *lengthPtr = reinterpret_cast<const uint16_t *>(base + offset);
	uint16_t length = *lengthPtr;
	size_t bytesNeeded = sizeof(uint16_t) + static_cast<size_t>(length) * sizeof(uint16_t);
	if (!resourceOffsetInRange(offset, bytesNeeded, rsrcSize))
		return false;
	if (length != value.size())
		return false;
	const uint16_t *str = lengthPtr + 1;
	for (uint16_t i = 0; i < length; ++i) {
		if (str[i] != value[i])
			return false;
	}
	return true;
}

const ImageResourceDirectoryEntry *findEntry(const uint8_t *base, const ImageResourceDirectory *dir,
											 const wibo::ResourceIdentifier &ident, uint32_t rsrcSize) {
	const auto *entries = resourceEntries(dir);
	if (ident.isString) {
		for (uint16_t i = 0; i < dir->numberOfNamedEntries; ++i) {
			const auto &entry = entries[i];
			if (resourceNameEquals(base, entry.name, ident.name, rsrcSize))
				return &entry;
		}
		return nullptr;
	}
	for (uint16_t i = 0; i < dir->numberOfIdEntries; ++i) {
		const auto &entry = entries[dir->numberOfNamedEntries + i];
		if (!(entry.name & RESOURCE_NAME_IS_STRING) && (entry.name & 0xFFFFu) == (ident.id & 0xFFFFu))
			return &entry;
	}
	return nullptr;
}

const ImageResourceDirectory *entryAsDirectory(const uint8_t *base, const ImageResourceDirectoryEntry *entry,
											   uint32_t rsrcSize) {
	if (!(entry->offsetToData & RESOURCE_DATA_IS_DIRECTORY))
		return nullptr;
	uint32_t offset = entry->offsetToData & ~RESOURCE_DATA_IS_DIRECTORY;
	if (!resourceOffsetInRange(offset, sizeof(ImageResourceDirectory), rsrcSize))
		return nullptr;
	return reinterpret_cast<const ImageResourceDirectory *>(base + offset);
}

const wibo::ImageResourceDataEntry *entryAsData(const uint8_t *base, const ImageResourceDirectoryEntry *entry,
												uint32_t rsrcSize) {
	if (entry->offsetToData & RESOURCE_DATA_IS_DIRECTORY)
		return nullptr;
	uint32_t offset = entry->offsetToData;
	if (!resourceOffsetInRange(offset, sizeof(wibo::ImageResourceDataEntry), rsrcSize))
		return nullptr;
	return reinterpret_cast<const wibo::ImageResourceDataEntry *>(base + offset);
}

uint16_t primaryLang(uint16_t lang) { return lang & 0x3FFu; }

const ImageResourceDirectoryEntry *selectLanguageEntry(const ImageResourceDirectory *dir,
													   std::optional<uint16_t> desired, uint16_t &chosenLang) {
	const auto *entries = resourceEntries(dir);
	uint16_t total = dir->numberOfNamedEntries + dir->numberOfIdEntries;
	const ImageResourceDirectoryEntry *primaryMatch = nullptr;
	const ImageResourceDirectoryEntry *neutralMatch = nullptr;
	const ImageResourceDirectoryEntry *first = nullptr;
	for (uint16_t i = 0; i < total; ++i) {
		const auto &entry = entries[i];
		if (entry.name & RESOURCE_NAME_IS_STRING)
			continue;
		uint16_t lang = static_cast<uint16_t>(entry.name & 0xFFFFu);
		if (!first)
			first = &entry;
		if (desired && lang == desired.value()) {
			chosenLang = lang;
			return &entry;
		}
		if (!primaryMatch && desired && primaryLang(lang) == primaryLang(desired.value())) {
			primaryMatch = &entry;
		}
		if (!neutralMatch && lang == 0)
			neutralMatch = &entry;
	}
	if (primaryMatch) {
		chosenLang = static_cast<uint16_t>(primaryMatch->name & 0xFFFFu);
		return primaryMatch;
	}
	if (neutralMatch) {
		chosenLang = 0;
		return neutralMatch;
	}
	if (first) {
		chosenLang = static_cast<uint16_t>(first->name & 0xFFFFu);
		return first;
	}
	return nullptr;
}

} // namespace

namespace wibo {

bool Executable::findResource(const ResourceIdentifier &type, const ResourceIdentifier &name,
							  std::optional<uint16_t> language, ResourceLocation &out) const {
	const uint8_t *base = reinterpret_cast<const uint8_t *>(rsrcBase);
	if (!base) {
		wibo::lastError = ERROR_RESOURCE_DATA_NOT_FOUND;
		return false;
	}
	const auto *root = reinterpret_cast<const ImageResourceDirectory *>(base);
	const auto *typeEntry = findEntry(base, root, type, rsrcSize);
	if (!typeEntry) {
		wibo::lastError = ERROR_RESOURCE_TYPE_NOT_FOUND;
		return false;
	}
	const auto *nameDir = entryAsDirectory(base, typeEntry, rsrcSize);
	if (!nameDir) {
		wibo::lastError = ERROR_RESOURCE_DATA_NOT_FOUND;
		return false;
	}
	const auto *nameEntry = findEntry(base, nameDir, name, rsrcSize);
	if (!nameEntry) {
		wibo::lastError = ERROR_RESOURCE_NAME_NOT_FOUND;
		return false;
	}
	const auto *langDir = entryAsDirectory(base, nameEntry, rsrcSize);
	if (!langDir) {
		wibo::lastError = ERROR_RESOURCE_DATA_NOT_FOUND;
		return false;
	}
	uint16_t chosenLang = language.value_or(0);
	const auto *langEntry = selectLanguageEntry(langDir, language, chosenLang);
	if (!langEntry) {
		wibo::lastError = ERROR_RESOURCE_LANG_NOT_FOUND;
		return false;
	}
	const auto *dataEntry = entryAsData(base, langEntry, rsrcSize);
	if (!dataEntry) {
		wibo::lastError = ERROR_RESOURCE_DATA_NOT_FOUND;
		return false;
	}
	out.dataEntry = dataEntry;
	out.data = fromRVA<const void>(dataEntry->offsetToData);
	out.size = dataEntry->size;
	out.language = chosenLang;
	return true;
}

bool resourceEntryBelongsToExecutable(const Executable &exe, const ImageResourceDataEntry *entry) {
	if (!entry || !exe.rsrcBase)
		return false;
	const auto *base = reinterpret_cast<const uint8_t *>(exe.rsrcBase);
	const auto *ptr = reinterpret_cast<const uint8_t *>(entry);
	if (exe.rsrcSize == 0)
		return true;
	return ptr >= base && (ptr + sizeof(*entry)) <= (base + exe.rsrcSize);
}

static bool isIntegerIdentifier(const void *ptr) { return ((uintptr_t)ptr >> 16) == 0; }

static std::u16string ansiToU16String(const char *str) {
	std::u16string result;
	if (!str)
		return result;
	while (*str) {
		result.push_back(static_cast<unsigned char>(*str++));
	}
	return result;
}

static std::u16string wideToU16String(const uint16_t *str) {
	std::u16string result;
	if (!str)
		return result;
	while (*str) {
		result.push_back(*str++);
	}
	return result;
}

ResourceIdentifier resourceIdentifierFromAnsi(const char *id) {
	if (!id) {
		return ResourceIdentifier::fromID(0);
	}
	if (isIntegerIdentifier(id)) {
		return ResourceIdentifier::fromID(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(id)));
	}
	return ResourceIdentifier::fromString(ansiToU16String(id));
}

ResourceIdentifier resourceIdentifierFromWide(const uint16_t *id) {
	if (!id) {
		return ResourceIdentifier::fromID(0);
	}
	if (isIntegerIdentifier(id)) {
		return ResourceIdentifier::fromID(static_cast<uint32_t>(reinterpret_cast<uintptr_t>(id)));
	}
	return ResourceIdentifier::fromString(wideToU16String(id));
}

} // namespace wibo
