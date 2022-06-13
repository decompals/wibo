#include "common.h"
#include <asm/ldt.h>
#include <errno.h>
#include <memory>
#include <sys/mman.h>
#include <sys/syscall.h>

uint32_t wibo::lastError = 0;
char *wibo::commandLine;

void stub() {
	// should go through all the functions imported by mwcceppc.exe
	// and create template stubs for them, at least...
	printf("Unhandled function\n");
	exit(0);
}

uint32_t __attribute__((stdcall)) CoInitialize(void *pvReserved) {
	printf("CoInitialize(...)\n");
	return 0; // S_OK I think?
}

void *wibo::resolveStubByName(const char *dllName, const char *funcName) {
	if (strcmp(dllName, "KERNEL32.dll") == 0) {
		void *func = wibo::resolveKernel32(funcName);
		if (func)
			return func;
	}
	if (strcmp(dllName, "ADVAPI32.dll") == 0) {
		void *func = wibo::resolveAdvApi32(funcName);
		if (func)
			return func;
	}
	if (strcmp(dllName, "ole32.dll") == 0) {
		if (strcmp(funcName, "CoInitialize") == 0) return (void *) CoInitialize;
	}

	printf("Missing function: %s (%s)\n", dllName, funcName);
	return (void *) stub;
}

void *wibo::resolveStubByOrdinal(const char *dllName, uint16_t ordinal) {
	return (void *) stub;
}

// Windows Thread Information Block
struct TIB {
	void *sehFrame;
	void *stackBase;
	void *stackLimit;
	void *subSystemTib;
	void *fiberData;
	void *arbitraryDataSlot;
	TIB *tib;
};

int main(int argc, char **argv) {
	// Create TIB
	TIB tib;
	tib.tib = &tib;

	struct user_desc tibDesc;
	tibDesc.entry_number = 0;
	tibDesc.base_addr = (unsigned int) &tib;
	tibDesc.limit = 0x1000;
	tibDesc.seg_32bit = 1;
	tibDesc.contents = 0; // hopefully this is ok
	tibDesc.read_exec_only = 0;
	tibDesc.limit_in_pages = 0;
	tibDesc.seg_not_present = 0;
	tibDesc.useable = 1;
	if (syscall(SYS_modify_ldt, 1, &tibDesc, sizeof tibDesc) != 0) {
		perror("Failed to modify LDT\n");
		return 1;
	}

	// Build a command line (todo, fill this with argv etc)
	wibo::commandLine = new char[1024];
	strcpy(wibo::commandLine, "mwcceppc.exe");

	wibo::Executable exec;

	FILE *f = fopen("mwcceppc.exe", "rb");
	exec.loadPE(f);
	fclose(f);

	uint16_t tibSegment = (tibDesc.entry_number << 3) | 7;
	// Invoke the damn thing
	asm(
		"movw %0, %%fs; call *%1"
		:
		: "r"(tibSegment), "r"(exec.entryPoint)
	);
	printf("We came back\n");

	return 0;
}
