#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define WIN_FUNC __attribute__((stdcall))

namespace wibo {
	extern uint32_t lastError;
	extern char *commandLine;

	void *resolveKernel32(const char *name);
	void *resolveAdvApi32(const char *name);
	void *resolveStubByName(const char *dllName, const char *funcName);
	void *resolveStubByOrdinal(const char *dllName, uint16_t ordinal);

	struct Executable {
		Executable();
		~Executable();
		bool loadPE(FILE *file);

		void *imageBuffer;
		size_t imageSize;
		void *entryPoint;

		template <typename T>
		T *fromRVA(uint32_t rva) {
			return (T *) (rva + (uint8_t *) imageBuffer);
		}

		template <typename T>
		T *fromRVA(T *rva) {
			return fromRVA<T>((uint32_t) rva);
		}
	};
}
