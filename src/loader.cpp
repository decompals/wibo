#include "common.h"
#include "errors.h"
#include "heap.h"
#include "kernel32/internal.h"
#include "modules.h"
#include "types.h"

#include <algorithm>
#include <cstring>
#include <strings.h>
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
	PEImageDataDirectory importTable;	// *
	PEImageDataDirectory resourceTable; // *
	PEImageDataDirectory exceptionTable;
	PEImageDataDirectory certificateTable;
	PEImageDataDirectory baseRelocationTable; // *
	PEImageDataDirectory debug;				  // *
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

struct PEDelayImportDescriptor {
	uint32_t attributes;
	uint32_t name;
	uint32_t moduleHandle;
	uint32_t importAddressTable;
	uint32_t importNameTable;
	uint32_t boundImportAddressTable;
	uint32_t unloadInformationTable;
	uint32_t timeStamp;
};

struct PEBaseRelocationBlock {
	uint32_t virtualAddress;
	uint32_t sizeOfBlock;
};

constexpr uint16_t IMAGE_REL_BASED_ABSOLUTE = 0;
constexpr uint16_t IMAGE_REL_BASED_HIGHLOW = 3;

constexpr uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
constexpr uint32_t IMAGE_SCN_MEM_READ = 0x40000000;
constexpr uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000;
constexpr uint32_t IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;

static uintptr_t alignDown(uintptr_t value, size_t alignment) {
	if (alignment == 0) {
		return value;
	}
	return value - (value % alignment);
}

static uintptr_t alignUp(uintptr_t value, size_t alignment) {
	if (alignment == 0) {
		return value;
	}
	const uintptr_t remainder = value % alignment;
	if (remainder == 0) {
		return value;
	}
	if (value > std::numeric_limits<uintptr_t>::max() - (alignment - remainder)) {
		return std::numeric_limits<uintptr_t>::max();
	}
	return value + (alignment - remainder);
}

static DWORD sectionProtectFromCharacteristics(uint32_t characteristics) {
	const bool executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
	bool readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
	const bool writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
	if (!readable && !writable && !executable) {
		readable = true;
	}
	DWORD protect = PAGE_NOACCESS;
	if (executable) {
		if (writable) {
			protect = PAGE_EXECUTE_READWRITE;
		} else if (readable) {
			protect = PAGE_EXECUTE_READ;
		} else {
			protect = PAGE_EXECUTE;
		}
	} else {
		if (writable) {
			protect = PAGE_READWRITE;
		} else if (readable) {
			protect = PAGE_READONLY;
		}
	}
	if ((characteristics & IMAGE_SCN_MEM_NOT_CACHED) != 0) {
		protect |= PAGE_NOCACHE;
	}
	return protect;
}

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

wibo::Executable::~Executable() {
	if (imageBase) {
		wibo::heap::virtualFree(imageBase, 0, MEM_RELEASE);
		imageBase = nullptr;
	}
}

/**
 * Load a PE file into memory.
 *
 * @param file The file to load.
 * @param exec Whether to make the loaded image executable.
 */
bool wibo::Executable::loadPE(FILE *file, bool exec) {
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
	fread(&header32, std::min(sizeof(header32), (size_t)header.sizeOfOptionalHeader), 1, file);
	if (header32.magic != 0x10B)
		return false;

	DEBUG_LOG("Image Base: %x / Size: %x\n", header32.imageBase, header32.sizeOfImage);

	long pageSize = sysconf(_SC_PAGE_SIZE);
	DEBUG_LOG("Page size: %x\n", (unsigned int)pageSize);
	const size_t pageSizeValue = pageSize > 0 ? static_cast<size_t>(pageSize) : static_cast<size_t>(4096);

	preferredImageBase = header32.imageBase;
	exportDirectoryRVA = header32.exportTable.virtualAddress;
	exportDirectorySize = header32.exportTable.size;
	relocationDirectoryRVA = header32.baseRelocationTable.virtualAddress;
	relocationDirectorySize = header32.baseRelocationTable.size;
	importDirectoryRVA = header32.importTable.virtualAddress;
	importDirectorySize = header32.importTable.size;
	delayImportDirectoryRVA = header32.delayImportDescriptor.virtualAddress;
	delayImportDirectorySize = header32.delayImportDescriptor.size;
	tlsDirectoryRVA = header32.tlsTable.virtualAddress;
	tlsDirectorySize = header32.tlsTable.size;
	execMapped = exec;
	importsResolved = false;
	importsResolving = false;

	// Build buffer
	imageSize = header32.sizeOfImage;
	DWORD initialProtect = exec ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
	void *preferredBase = reinterpret_cast<void *>(static_cast<uintptr_t>(header32.imageBase));
	void *allocatedBase = preferredBase;
	std::size_t allocationSize = static_cast<std::size_t>(header32.sizeOfImage);
	wibo::heap::VmStatus allocStatus = wibo::heap::virtualAlloc(
		&allocatedBase, &allocationSize, MEM_RESERVE | MEM_COMMIT, initialProtect, MEM_IMAGE);
	if (allocStatus != wibo::heap::VmStatus::Success) {
		DEBUG_LOG("loadPE: preferred base allocation failed (status=%u), retrying anywhere\n",
			  static_cast<unsigned>(allocStatus));
		allocatedBase = nullptr;
		allocationSize = static_cast<std::size_t>(header32.sizeOfImage);
		allocStatus = wibo::heap::virtualAlloc(
			&allocatedBase, &allocationSize, MEM_RESERVE | MEM_COMMIT, initialProtect, MEM_IMAGE);
	}
	if (allocStatus != wibo::heap::VmStatus::Success) {
		DEBUG_LOG("Image mapping failed (status=%u)\n", static_cast<unsigned>(allocStatus));
		imageBase = nullptr;
		return false;
	}
	imageBase = allocatedBase;
	relocationDelta =
		static_cast<intptr_t>(reinterpret_cast<uintptr_t>(imageBase) - static_cast<uintptr_t>(header32.imageBase));
	memset(imageBase, 0, header32.sizeOfImage);
	sections.clear();
	uintptr_t imageBaseAddr = reinterpret_cast<uintptr_t>(imageBase);
	uintptr_t headerSpan = alignUp(static_cast<uintptr_t>(header32.sizeOfHeaders), pageSizeValue);
	if (headerSpan != 0) {
		Executable::SectionInfo headerInfo{};
		headerInfo.base = imageBaseAddr;
		headerInfo.size = static_cast<size_t>(headerSpan);
		headerInfo.protect = PAGE_READONLY;
		sections.push_back(headerInfo);
	}

	// Read the sections
	fseek(file, offsetToPE + sizeof header + header.sizeOfOptionalHeader, SEEK_SET);

	for (int i = 0; i < header.numberOfSections; i++) {
		PESectionHeader section;
		fread(&section, sizeof section, 1, file);

		char name[9];
		memcpy(name, section.name, 8);
		name[8] = 0;
		DEBUG_LOG("Section %d: name=%s addr=%x size=%x (raw=%x) ptr=%x\n", i, name, section.virtualAddress,
				  section.virtualSize, section.sizeOfRawData, section.pointerToRawData);

		void *sectionBase = (void *)((uintptr_t)imageBase + section.virtualAddress);
		if (section.pointerToRawData > 0 && section.sizeOfRawData > 0) {
			// Grab this data
			long savePos = ftell(file);
			fseek(file, section.pointerToRawData, SEEK_SET);
			fread(sectionBase, section.sizeOfRawData, 1, file);
			fseek(file, savePos, SEEK_SET);
		}

		if (strcmp(name, ".rsrc") == 0) {
			rsrcBase = sectionBase;
			rsrcSize = std::max(section.virtualSize, section.sizeOfRawData);
		}

		size_t sectionSpan = std::max(section.virtualSize, section.sizeOfRawData);
		if (sectionSpan != 0) {
			uintptr_t sectionStart =
				alignDown(imageBaseAddr + static_cast<uintptr_t>(section.virtualAddress), pageSizeValue);
			uintptr_t sectionEnd = alignUp(imageBaseAddr + static_cast<uintptr_t>(section.virtualAddress) +
											   static_cast<uintptr_t>(sectionSpan),
										   pageSizeValue);
			if (sectionEnd > sectionStart) {
				Executable::SectionInfo sectionInfo{};
				sectionInfo.base = sectionStart;
				sectionInfo.size = static_cast<size_t>(sectionEnd - sectionStart);
				sectionInfo.protect = sectionProtectFromCharacteristics(section.characteristics);
				sectionInfo.characteristics = section.characteristics;
				sections.push_back(sectionInfo);
			}
		}
	}
	std::sort(sections.begin(), sections.end(),
			  [](const SectionInfo &lhs, const SectionInfo &rhs) { return lhs.base < rhs.base; });

	if (exec && relocationDelta != 0) {
		if (relocationDirectoryRVA == 0 || relocationDirectorySize == 0) {
			DEBUG_LOG("Relocation required but no relocation directory present\n");
			wibo::heap::virtualFree(imageBase, 0, MEM_RELEASE);
			imageBase = nullptr;
			return false;
		}

		uint8_t *relocCursor = fromRVA<uint8_t>(relocationDirectoryRVA);
		uint8_t *relocEnd = relocCursor + relocationDirectorySize;
		while (relocCursor < relocEnd) {
			auto *block = reinterpret_cast<PEBaseRelocationBlock *>(relocCursor);
			if (block->sizeOfBlock < sizeof(PEBaseRelocationBlock) ||
				block->sizeOfBlock > static_cast<uint32_t>(relocEnd - relocCursor)) {
				break;
			}
			if (block->sizeOfBlock == sizeof(PEBaseRelocationBlock)) {
				break;
			}
			size_t entryCount = (block->sizeOfBlock - sizeof(PEBaseRelocationBlock)) / sizeof(uint16_t);
			auto *entries = reinterpret_cast<uint16_t *>(relocCursor + sizeof(PEBaseRelocationBlock));
			for (size_t i = 0; i < entryCount; ++i) {
				uint16_t entry = entries[i];
				uint16_t type = entry >> 12;
				uint16_t offset = entry & 0x0FFF;
				if (type == IMAGE_REL_BASED_ABSOLUTE)
					continue;
				uintptr_t target = reinterpret_cast<uintptr_t>(imageBase) + block->virtualAddress + offset;
				switch (type) {
				case IMAGE_REL_BASED_HIGHLOW: {
					auto *addr = reinterpret_cast<uint32_t *>(target);
					*addr += static_cast<uint32_t>(relocationDelta);
					break;
				}
				default:
					DEBUG_LOG("Unhandled relocation type %u at %08x\n", type, block->virtualAddress + offset);
					break;
				}
			}
			relocCursor += block->sizeOfBlock;
		}
	}

	entryPoint = header32.addressOfEntryPoint ? fromRVA<void>(header32.addressOfEntryPoint) : nullptr;

	return true;
}

bool wibo::Executable::resolveImports() {
	auto finalizeSections = [this]() -> bool {
		if (!execMapped || sectionsProtected) {
			return true;
		}
		for (const auto &section : sections) {
			if (section.size == 0) {
				continue;
			}
			void *sectionAddress = reinterpret_cast<void *>(section.base);
			wibo::heap::VmStatus status =
				wibo::heap::virtualProtect(sectionAddress, section.size, section.protect, nullptr);
			if (status != wibo::heap::VmStatus::Success) {
				DEBUG_LOG("resolveImports: failed to set section protection at %p (size=%zu, protect=0x%x) status=%u\n",
					  sectionAddress, section.size, section.protect, static_cast<unsigned>(status));
				kernel32::setLastError(wibo::heap::win32ErrorFromVmStatus(status));
				return false;
			}
		}
		sectionsProtected = true;
		return true;
	};

	if (importsResolved || !execMapped) {
		importsResolved = true;
		importsResolving = false;
		if (!finalizeSections()) {
			return false;
		}
		return true;
	}
	if (importsResolving) {
		return true;
	}
	importsResolving = true;

	if (!importDirectoryRVA) {
		importsResolved = true;
		importsResolving = false;
		if (!finalizeSections()) {
			return false;
		}
		return true;
	}

	PEImportDirectoryEntry *dir = fromRVA<PEImportDirectoryEntry>(importDirectoryRVA);
	if (!dir) {
		importsResolved = true;
		importsResolving = false;
		if (!finalizeSections()) {
			return false;
		}
		return true;
	}

	while (dir->name) {
		char *dllName = fromRVA(dir->name);
		DEBUG_LOG("DLL Name: %s\n", dllName);
		uint32_t *lookupTable = fromRVA(dir->importLookupTable);
		uint32_t *addressTable = fromRVA(dir->importAddressTable);

		ModuleInfo *module = loadModule(dllName);
		if (!module && kernel32::getLastError() != ERROR_MOD_NOT_FOUND) {
			DEBUG_LOG("Failed to load import module %s\n", dllName);
			// lastError is set by loadModule
			importsResolved = false;
			importsResolving = false;
			return false;
		}

		while (*lookupTable) {
			uint32_t lookup = *lookupTable;
			if (lookup & 0x80000000) {
				// Import by ordinal
				uint16_t ordinal = lookup & 0xFFFF;
				DEBUG_LOG("  Ordinal: %d\n", ordinal);
				void *func =
					module ? resolveFuncByOrdinal(module, ordinal) : resolveMissingImportByOrdinal(dllName, ordinal);
				DEBUG_LOG("    -> %p\n", func);
				*addressTable = reinterpret_cast<uintptr_t>(func);
			} else {
				// Import by name
				PEHintNameTableEntry *hintName = fromRVA<PEHintNameTableEntry>(lookup);
				DEBUG_LOG("  Name: %s (IAT=%p)\n", hintName->name, addressTable);
				void *func = module ? resolveFuncByName(module, hintName->name)
									: resolveMissingImportByName(dllName, hintName->name);
				DEBUG_LOG("    -> %p\n", func);
				*addressTable = reinterpret_cast<uintptr_t>(func);
			}
			++lookupTable;
			++addressTable;
		}
		++dir;
	}

	// TODO: actual delay loading from __delayLoadHelper2
	// if (delayImportDirectoryRVA) {
	// 	DEBUG_LOG("Processing delay import table at RVA %x\n", delayImportDirectoryRVA);
	// 	PEDelayImportDescriptor *delay = fromRVA<PEDelayImportDescriptor>(delayImportDirectoryRVA);
	// 	while (delay && delay->name) {
	// 		char *dllName = fromRVA<char>(delay->name);
	// 		DEBUG_LOG("Delay DLL Name: %s\n", dllName);
	// 		uint32_t *lookupTable = fromRVA<uint32_t>(delay->importNameTable);
	// 		uint32_t *addressTable = fromRVA<uint32_t>(delay->importAddressTable);
	// 		ModuleInfo *module = loadModule(dllName);
	// 		while (*lookupTable) {
	// 			uint32_t lookup = *lookupTable;
	// 			if (lookup & 0x80000000) {
	// 				uint16_t ordinal = lookup & 0xFFFF;
	// 				DEBUG_LOG("  Ordinal: %d (IAT=%p)\n", ordinal, addressTable);
	// 				void *func = module ? resolveFuncByOrdinal(module, ordinal)
	// 									: resolveMissingImportByOrdinal(dllName, ordinal);
	// 				*addressTable = reinterpret_cast<uintptr_t>(func);
	// 			} else {
	// 				PEHintNameTableEntry *hintName = fromRVA<PEHintNameTableEntry>(lookup);
	// 				DEBUG_LOG("  Name: %s\n", hintName->name);
	// 				void *func = module ? resolveFuncByName(module, hintName->name)
	// 									: resolveMissingImportByName(dllName, hintName->name);
	// 				*addressTable = reinterpret_cast<uintptr_t>(func);
	// 			}
	// 			++lookupTable;
	// 			++addressTable;
	// 		}
	// 		if (delay->moduleHandle) {
	// 			HMODULE *moduleSlot = fromRVA<HMODULE>(delay->moduleHandle);
	// 			if (moduleSlot) {
	// 				*moduleSlot = module;
	// 			}
	// 		}
	// 		++delay;
	// 	}
	// }

	importsResolved = true;
	importsResolving = false;
	if (!finalizeSections()) {
		importsResolved = false;
		return false;
	}
	return true;
}
