#include "common.h"

namespace user32 {
	struct Resource {
		uint32_t id;
		uint32_t value;
	};

	struct ResourceTable {
		char pad[12];
		uint16_t nameEntryCount;
		uint16_t idEntryCount;
		Resource resources[];
	};

	static unsigned int searchResourceTableByID(const char *tableAddr, unsigned int id) {
		ResourceTable* table = (ResourceTable*)tableAddr;
		for (int i = 0; i < table->idEntryCount; i++) {
			const Resource& r = table->resources[table->nameEntryCount + i];
			if (r.id == id) {
				return r.value;
			}
		}
		return 0;
	}

	static unsigned int* getResourceByID(wibo::Executable *mod, unsigned int typeID, unsigned int nameID, unsigned int languageID) {
		const char *rsrcBase = (const char *)mod->rsrcBase;

		if (rsrcBase == 0) {
			DEBUG_LOG("getResourceByID: no .rsrc section\n");
			wibo::lastError = 1812; // ERROR_RESOURCE_DATA_NOT_FOUND
			return 0;
		}

		unsigned int typeTable = searchResourceTableByID(rsrcBase, typeID) & 0x7FFFFFFFu;
		if (typeTable == 0) {
			DEBUG_LOG("getResourceByID: no type table with id = %s\n", typeID);
			wibo::lastError = 1813; // ERROR_RESOURCE_TYPE_NOT_FOUND
			return 0;
		}

		unsigned int nameTable = searchResourceTableByID(rsrcBase + typeTable, nameID) & 0x7FFFFFFFu;
		if (nameTable == 0) {
			DEBUG_LOG("getResourceByID: no name table with id = %s\n", nameID);
			wibo::lastError = 1814; // ERROR_RESOURCE_NAME_NOT_FOUND
			return 0;
		}

		unsigned int langEntry = searchResourceTableByID(rsrcBase + nameTable, languageID);
		if (langEntry == 0) {
			DEBUG_LOG("getResourceByID: no lang entry with id = %s\n", languageID);
			wibo::lastError = 1814; // ERROR_RESOURCE_NAME_NOT_FOUND
			return 0;
		}

		return (unsigned int*)(rsrcBase + langEntry);
	}

	static const char *getStringFromTable(unsigned int uID) {
		wibo::Executable *mod = wibo::mainModule;
		unsigned int tableID = (uID >> 4) + 1;
		unsigned int entryID = uID & 15;
		unsigned int* stringTable = getResourceByID(mod, 6, tableID, 1033);
		if (stringTable == 0)
			return 0;

		// what's in here?
		const char *str = mod->fromRVA<const char>(stringTable[0]);
		unsigned int size = stringTable[1];
		assert(entryID < size);

		// skip over strings to get to the one we want
		for (unsigned int i = 0; i < entryID; i++) {
			int stringSize = *(uint16_t*)str;
			str += 2;
			str += stringSize * 2;
		}

		return str;
	}

	int WIN_FUNC LoadStringA(void* hInstance, unsigned int uID, char* lpBuffer, int cchBufferMax) {
		DEBUG_LOG("LoadStringA %p %d %d\n", hInstance, uID, cchBufferMax);
		const char* s = getStringFromTable(uID);
		if (!s) {
			return 0;
		}
		int len = *(int16_t*)s;
		s += 2;
		assert(cchBufferMax != 0);
		len = (len < cchBufferMax - 1 ? len : cchBufferMax - 1);
		for (int i = 0; i < len; i++) {
			lpBuffer[i] = s[i * 2];
		}
		lpBuffer[len] = 0;
		DEBUG_LOG("returning: %s\n", lpBuffer);
		return len;
	}

	int WIN_FUNC MessageBoxA(void *hwnd, const char *lpText, const char *lpCaption, unsigned int uType) {
		printf("MESSAGE BOX: [%s] %s\n", lpCaption, lpText);
		fflush(stdout);
		return 1;
	}
}

static void *resolveByName(const char *name) {
	if (strcmp(name, "LoadStringA") == 0) return (void *) user32::LoadStringA;
	if (strcmp(name, "MessageBoxA") == 0) return (void *) user32::MessageBoxA;
	return nullptr;
}

wibo::Module lib_user32 = {
	(const char *[]){
		"user32",
		"user32.dll",
		nullptr,
	},
	resolveByName,
	nullptr,
};
