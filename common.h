#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>

#define WIN_FUNC __attribute__((stdcall))
#define DEBUG_LOG(...) wibo::debug_log(__VA_ARGS__)

namespace wibo {
	extern uint32_t lastError;
	extern char *commandLine;
	extern bool debugEnabled;

	void debug_log(const char *fmt, ...);

	void *resolveVersion(const char *name);
	void *resolveKernel32(const char *name);
	void *resolveUser32(const char *name);
	void *resolveOle32(const char *name);
	void *resolveAdvApi32(const char *name);
	void *resolveLmgr(uint16_t ordinal);
	void *resolveFuncByName(const char *dllName, const char *funcName);
	void *resolveFuncByOrdinal(const char *dllName, uint16_t ordinal);

	struct Executable {
		Executable();
		~Executable();
		bool loadPE(FILE *file);

		void *imageBuffer;
		size_t imageSize;
		void *entryPoint;
		void *rsrcBase;

		template <typename T>
		T *fromRVA(uint32_t rva) {
			return (T *) (rva + (uint8_t *) imageBuffer);
		}

		template <typename T>
		T *fromRVA(T *rva) {
			return fromRVA<T>((uint32_t) rva);
		}
	};

	extern Executable *mainModule;
}
