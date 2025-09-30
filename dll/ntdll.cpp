#include "common.h"
#include "errors.h"
#include "files.h"

#include <sys/mman.h>

#include <optional>

#define PIO_APC_ROUTINE void *

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

namespace kernel32 {
BOOL WIN_FUNC SetEvent(HANDLE hEvent);
BOOL WIN_FUNC ResetEvent(HANDLE hEvent);
} // namespace kernel32

namespace ntdll {

NTSTATUS WIN_FUNC NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
							 PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
							 PULONG Key) {
	DEBUG_LOG("NtReadFile(%p, %p, %p, %p, %p, %p, %u, %p, %p) ", FileHandle, Event, ApcRoutine, ApcContext,
			  IoStatusBlock, Buffer, Length, ByteOffset, Key);
	(void)ApcRoutine;
	(void)ApcContext;
	(void)Key;

	if (!IoStatusBlock) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return STATUS_INVALID_PARAMETER;
	}

	auto file = files::fileHandleFromHandle(FileHandle);
	if (!file || !file->fp) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		IoStatusBlock->Status = STATUS_INVALID_HANDLE;
		IoStatusBlock->Information = 0;
		return STATUS_INVALID_HANDLE;
	}

	bool handleOverlapped = (file->flags & FILE_FLAG_OVERLAPPED) != 0;
	std::optional<uint64_t> offset;
	bool updateFilePointer = !handleOverlapped;
	if (ByteOffset) {
		offset = static_cast<uint64_t>(*ByteOffset);
	} else if (handleOverlapped) {
		updateFilePointer = false;
	}

	if (Event) {
		kernel32::ResetEvent(Event);
	}

	auto io = files::read(file, Buffer, Length, offset, updateFilePointer);
	DWORD winError = ERROR_SUCCESS;
	NTSTATUS status = STATUS_SUCCESS;
	if (io.unixError != 0) {
		winError = wibo::winErrorFromErrno(io.unixError);
		status = wibo::statusFromWinError(winError);
	} else if (io.reachedEnd && io.bytesTransferred == 0) {
		winError = ERROR_HANDLE_EOF;
		status = STATUS_END_OF_FILE;
	}

	IoStatusBlock->Status = status;
	IoStatusBlock->Information = static_cast<ULONG_PTR>(io.bytesTransferred);
	wibo::lastError = winError;

	if (Event) {
		kernel32::SetEvent(Event);
	}

	DEBUG_LOG("-> 0x%x\n", status);
	return status;
}

#define PAGE_NOACCESS 0x1
#define PAGE_READONLY 0x2
#define PAGE_READWRITE 0x4
#define PAGE_WRITECOPY 0x8
#define PAGE_EXECUTE 0x10
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80
#define PAGE_GUARD 0x100
#define PAGE_NOCACHE 0x200
#define PAGE_WRITECOMBINE 0x400

NTSTATUS WIN_FUNC NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
										  PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
	DEBUG_LOG("NtAllocateVirtualMemory(%p, %p, %lu, %p, %lu, %lu) ", ProcessHandle, BaseAddress, ZeroBits, RegionSize,
			  AllocationType, Protect);
	assert(ProcessHandle == (HANDLE)-1);
	assert(ZeroBits == 0);

	int prot = 0;
	if (Protect & PAGE_NOACCESS)
		prot |= PROT_NONE;
	if (Protect & PAGE_READONLY)
		prot |= PROT_READ;
	if (Protect & PAGE_READWRITE)
		prot |= PROT_READ | PROT_WRITE;
	if (Protect & PAGE_WRITECOPY)
		prot |= PROT_READ | PROT_WRITE;
	if (Protect & PAGE_EXECUTE)
		prot |= PROT_EXEC;
	if (Protect & PAGE_EXECUTE_READ)
		prot |= PROT_EXEC | PROT_READ;
	if (Protect & PAGE_EXECUTE_READWRITE)
		prot |= PROT_EXEC | PROT_READ | PROT_WRITE;
	assert(!(Protect & PAGE_EXECUTE_WRITECOPY));
	assert(!(Protect & PAGE_GUARD));
	assert(!(Protect & PAGE_NOCACHE));
	assert(!(Protect & PAGE_WRITECOMBINE));

	void *addr = mmap(*BaseAddress, *RegionSize, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");
		return STATUS_NOT_SUPPORTED;
	}
	*BaseAddress = addr;

	DEBUG_LOG("-> 0x%x\n", STATUS_SUCCESS);
	return STATUS_SUCCESS;
}

NTSTATUS WIN_FUNC NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T NumberOfBytesToProtect,
										 ULONG NewAccessProtection, PULONG OldAccessProtection) {
	DEBUG_LOG("NtProtectVirtualMemory(%p, %p, %p, %lu, %p) ", ProcessHandle, BaseAddress, NumberOfBytesToProtect,
			  NewAccessProtection, OldAccessProtection);
	assert(ProcessHandle == (HANDLE)-1);
	assert(NumberOfBytesToProtect != nullptr);

	int prot = 0;
	if (NewAccessProtection & PAGE_NOACCESS)
		prot |= PROT_NONE;
	if (NewAccessProtection & PAGE_READONLY)
		prot |= PROT_READ;
	if (NewAccessProtection & PAGE_READWRITE)
		prot |= PROT_READ | PROT_WRITE;
	if (NewAccessProtection & PAGE_WRITECOPY)
		prot |= PROT_READ | PROT_WRITE;
	if (NewAccessProtection & PAGE_EXECUTE)
		prot |= PROT_EXEC;
	if (NewAccessProtection & PAGE_EXECUTE_READ)
		prot |= PROT_EXEC | PROT_READ;
	if (NewAccessProtection & PAGE_EXECUTE_READWRITE)
		prot |= PROT_EXEC | PROT_READ | PROT_WRITE;
	assert(!(NewAccessProtection & PAGE_EXECUTE_WRITECOPY));
	assert(!(NewAccessProtection & PAGE_GUARD));
	assert(!(NewAccessProtection & PAGE_NOCACHE));
	assert(!(NewAccessProtection & PAGE_WRITECOMBINE));

	int ret = mprotect(*BaseAddress, *NumberOfBytesToProtect, prot);
	if (ret != 0) {
		perror("mprotect");
		return STATUS_NOT_SUPPORTED;
	}

	if (OldAccessProtection) {
		*OldAccessProtection = 0; // stub
	}
	DEBUG_LOG("-> 0x%x\n", STATUS_SUCCESS);
	return STATUS_SUCCESS;
}

} // namespace ntdll

static void *resolveByName(const char *name) {
	if (strcmp(name, "NtReadFile") == 0)
		return (void *)ntdll::NtReadFile;
	if (strcmp(name, "NtAllocateVirtualMemory") == 0)
		return (void *)ntdll::NtAllocateVirtualMemory;
	if (strcmp(name, "NtProtectVirtualMemory") == 0)
		return (void *)ntdll::NtProtectVirtualMemory;
	return nullptr;
}

wibo::Module lib_ntdll = {
	(const char *[]){
		"ntdll",
		"ntdll.dll",
		nullptr,
	},
	resolveByName,
	nullptr,
};
