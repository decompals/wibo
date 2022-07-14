#include "common.h"
#include <algorithm>
#include <errno.h>
#include <memory>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

struct PEHeader {
	uint8_t magic[4]; // "PE\0\0"
	uint16_t machine;
	uint16_t numberOfSections;
	uint32_t timeDateStamp;
	uint32_t pointerToSymbolTable;
	uint32_t numberOfSymbols;
	uint16_t sizeOfOptionalHeader;
	uint16_t characteristics;
};
struct PEImageDataDirectory {
	uint32_t virtualAddress;
	uint32_t size;
};
struct PE32Header {
	uint16_t magic; // 0x10B for PE32
	uint8_t majorLinkerVersion;
	uint8_t minorLinkerVersion;
	uint32_t sizeOfCode;
	uint32_t sizeOfInitializedData;
	uint32_t sizeOfUninitializedData;
	uint32_t addressOfEntryPoint;
	uint32_t baseOfCode;
	uint32_t baseOfData;
	uint32_t imageBase;
	uint32_t sectionAlignment;
	uint32_t fileAlignment;
	uint16_t majorOperatingSystemVersion;
	uint16_t minorOperatingSystemVersion;
	uint16_t majorImageVersion;
	uint16_t minorImageVersion;
	uint16_t majorSubsystemVersion;
	uint16_t minorSubsystemVersion;
	uint32_t win32VersionValue;
	uint32_t sizeOfImage;
	uint32_t sizeOfHeaders;
	uint32_t checkSum;
	uint16_t subsystem;
	uint16_t dllCharacteristics;
	uint32_t sizeOfStackReserve;
	uint32_t sizeOfStackCommit;
	uint32_t sizeOfHeapReserve;
	uint32_t sizeOfHeapCommit;
	uint32_t loaderFlags;
	uint32_t numberOfRvaAndSizes;
	PEImageDataDirectory exportTable;
	PEImageDataDirectory importTable; // *
	PEImageDataDirectory resourceTable; // *
	PEImageDataDirectory exceptionTable;
	PEImageDataDirectory certificateTable;
	PEImageDataDirectory baseRelocationTable; // *
	PEImageDataDirectory debug; // *
	PEImageDataDirectory architecture;
	PEImageDataDirectory globalPtr;
	PEImageDataDirectory tlsTable;
	PEImageDataDirectory loadConfigTable;
	PEImageDataDirectory boundImport;
	PEImageDataDirectory iat;
	PEImageDataDirectory delayImportDescriptor;
	PEImageDataDirectory clrRuntimeHeader;
	PEImageDataDirectory reserved;
};
struct PESectionHeader {
	char name[8];
	uint32_t virtualSize;
	uint32_t virtualAddress;
	uint32_t sizeOfRawData;
	uint32_t pointerToRawData;
	uint32_t pointerToRelocations;
	uint32_t pointerToLinenumbers;
	uint16_t numberOfRelocations;
	uint16_t numberOfLinenumbers;
	uint32_t characteristics;
};
struct PEImportDirectoryEntry {
	uint32_t *importLookupTable;
	uint32_t timeDateStamp;
	uint32_t forwarderChain;
	char *name;
	uint32_t *importAddressTable;
};
struct PEHintNameTableEntry {
	uint16_t hint;
	char name[1]; // variable length
};

uint16_t read16(FILE *file) {
	uint16_t v = 0;
	fread(&v, 2, 1, file);
	return v;
}
uint32_t read32(FILE *file) {
	uint32_t v = 0;
	fread(&v, 4, 1, file);
	return v;
}


wibo::Executable::Executable() {
	imageBuffer = nullptr;
	imageSize = 0;
	rsrcBase = 0;
}

wibo::Executable::~Executable() {
	if (imageBuffer) {
		munmap(imageBuffer, imageSize);
	}
}

bool wibo::Executable::loadPE(FILE *file) {
	// Skip to PE header
	fseek(file, 0x3C, SEEK_SET);
	uint32_t offsetToPE = read32(file);
	fseek(file, offsetToPE, SEEK_SET);

	// Read headers
	PEHeader header;
	fread(&header, sizeof header, 1, file);
	if (memcmp(header.magic, "PE\0\0", 4) != 0)
		return false;
	if (header.machine != 0x14C) // i386
		return false;

	DEBUG_LOG("Sections: %d / Size of optional header: %x\n", header.numberOfSections, header.sizeOfOptionalHeader);

	PE32Header header32;
	memset(&header32, 0, sizeof header32);
	fread(&header32, std::min(sizeof(header32), (size_t) header.sizeOfOptionalHeader), 1, file);
	if (header32.magic != 0x10B)
		return false;

	DEBUG_LOG("Image Base: %x / Size: %x\n", header32.imageBase, header32.sizeOfImage);

	long pageSize = sysconf(_SC_PAGE_SIZE);
	DEBUG_LOG("Page size: %x\n", (unsigned int)pageSize);

	// Build buffer
	imageSize = header32.sizeOfImage;
	imageBuffer = mmap((void *) header32.imageBase, header32.sizeOfImage, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_FIXED|MAP_PRIVATE, -1, 0);
	memset(imageBuffer, 0, header32.sizeOfImage);
	if (imageBuffer == MAP_FAILED) {
		perror("Image mapping failed!");
		imageBuffer = 0;
		return false;
	}

	// Read the sections
	fseek(file, offsetToPE + sizeof header + header.sizeOfOptionalHeader, SEEK_SET);

	for (int i = 0; i < header.numberOfSections; i++) {
		PESectionHeader section;
		fread(&section, sizeof section, 1, file);

		char name[9];
		memcpy(name, section.name, 8);
		name[8] = 0;
		DEBUG_LOG("Section %d: name=%s addr=%x size=%x (raw=%x) ptr=%x\n", i, name, section.virtualAddress, section.virtualSize, section.sizeOfRawData, section.pointerToRawData);

		void *sectionBase = (void *) (header32.imageBase + section.virtualAddress);
		if (section.pointerToRawData > 0 && section.sizeOfRawData > 0) {
			// Grab this data
			long savePos = ftell(file);
			fseek(file, section.pointerToRawData, SEEK_SET);
			fread(sectionBase, section.sizeOfRawData, 1, file);
			fseek(file, savePos, SEEK_SET);
		}

		if (strcmp(name, ".rsrc") == 0) {
			rsrcBase = sectionBase;
		}
	}

	// Handle imports
	PEImportDirectoryEntry *dir = fromRVA<PEImportDirectoryEntry>(header32.importTable.virtualAddress);

	while (dir->name) {
		char *dllName = fromRVA(dir->name);
		DEBUG_LOG("DLL Name: %s\n", dllName);
		uint32_t *lookupTable = fromRVA(dir->importLookupTable);
		uint32_t *addressTable = fromRVA(dir->importAddressTable);

		while (*lookupTable) {
			uint32_t lookup = *lookupTable;
			if (lookup & 0x80000000) {
				// Import by ordinal
				uint16_t ordinal = lookup & 0xFFFF;
				DEBUG_LOG("  Ordinal: %d\n", ordinal);
				*addressTable = (uint32_t) resolveFuncByOrdinal(dllName, ordinal);
			} else {
				// Import by name
				PEHintNameTableEntry *hintName = fromRVA<PEHintNameTableEntry>(lookup);
				DEBUG_LOG("  Name: %s\n", hintName->name);
				*addressTable = (uint32_t) resolveFuncByName(dllName, hintName->name);
			}
			++lookupTable;
			++addressTable;
		}

		++dir;
	}

	entryPoint = fromRVA<void>(header32.addressOfEntryPoint);

	return true;
}
