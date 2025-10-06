#include "common.h"
#include "context.h"
#include "errors.h"
#include "files.h"
#include "handles.h"
#include "kernel32/internal.h"
#include "kernel32/processthreadsapi.h"
#include "modules.h"
#include "processes.h"
#include "strutil.h"

#include <sys/mman.h>
#include <unistd.h>

#include <optional>

#define PIO_APC_ROUTINE void *

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

namespace {

enum PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
};

struct PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PEB *PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
};

struct ProcessHandleDetails {
	pid_t pid = -1;
	DWORD exitCode = STILL_ACTIVE;
	PEB *peb = nullptr;
	bool isCurrentProcess = false;
};

constexpr LONG kDefaultBasePriority = 8;

struct RTL_OSVERSIONINFOW {
	ULONG dwOSVersionInfoSize;
	ULONG dwMajorVersion;
	ULONG dwMinorVersion;
	ULONG dwBuildNumber;
	ULONG dwPlatformId;
	WCHAR szCSDVersion[128];
};

using PRTL_OSVERSIONINFOW = RTL_OSVERSIONINFOW *;

struct RTL_OSVERSIONINFOEXW : RTL_OSVERSIONINFOW {
	WORD wServicePackMajor;
	WORD wServicePackMinor;
	WORD wSuiteMask;
	BYTE wProductType;
	BYTE wReserved;
};

using PRTL_OSVERSIONINFOEXW = RTL_OSVERSIONINFOEXW *;

constexpr ULONG kOsMajorVersion = 6;
constexpr ULONG kOsMinorVersion = 2;
constexpr ULONG kOsBuildNumber = 0;
constexpr ULONG kOsPlatformId = 2;			// VER_PLATFORM_WIN32_NT
constexpr BYTE kProductTypeWorkstation = 1; // VER_NT_WORKSTATION

bool resolveProcessDetails(HANDLE processHandle, ProcessHandleDetails &details) {
	if (kernel32::isPseudoCurrentProcessHandle(processHandle)) {
		details.pid = getpid();
		details.exitCode = STILL_ACTIVE;
		details.peb = wibo::processPeb;
		details.isCurrentProcess = true;
		return true;
	}

	auto po = wibo::handles().getAs<ProcessObject>(processHandle);
	if (!po) {
		return false;
	}

	details.pid = po->pid;
	details.exitCode = po->exitCode;
	details.isCurrentProcess = po->pid == getpid();
	details.peb = details.isCurrentProcess ? wibo::processPeb : nullptr;
	return true;
}

std::string windowsImagePathFor(const ProcessHandleDetails &details) {
	if (details.isCurrentProcess && !wibo::guestExecutablePath.empty()) {
		return files::pathToWindows(files::canonicalPath(wibo::guestExecutablePath));
	}

	std::error_code ec;
	std::filesystem::path link = std::filesystem::path("/proc") / std::to_string(details.pid) / "exe";
	std::filesystem::path resolved = std::filesystem::read_symlink(link, ec);
	if (!ec) {
		return files::pathToWindows(files::canonicalPath(resolved));
	}
	return std::string();
}

} // namespace

namespace kernel32 {
BOOL WIN_FUNC SetEvent(HANDLE hEvent);
BOOL WIN_FUNC ResetEvent(HANDLE hEvent);
} // namespace kernel32

namespace ntdll {

constexpr LARGE_INTEGER FILE_WRITE_TO_END_OF_FILE = static_cast<LARGE_INTEGER>(-1);
constexpr LARGE_INTEGER FILE_USE_FILE_POINTER_POSITION = static_cast<LARGE_INTEGER>(-2);

NTSTATUS WIN_FUNC NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
							 PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
							 PULONG Key) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("NtReadFile(%p, %p, %p, %p, %p, %p, %u, %p, %p) ", FileHandle, Event, ApcRoutine, ApcContext,
			  IoStatusBlock, Buffer, Length, ByteOffset, Key);
	(void)ApcRoutine;
	(void)ApcContext;
	(void)Key;

	if (!IoStatusBlock) {
		return STATUS_INVALID_PARAMETER;
	}
	IoStatusBlock->Information = 0;

	auto file = wibo::handles().getAs<FileObject>(FileHandle);
	if (!file || !file->valid()) {
		IoStatusBlock->Status = STATUS_INVALID_HANDLE;
		IoStatusBlock->Information = 0;
		return STATUS_INVALID_HANDLE;
	}

	bool useOverlapped = file->overlapped;
	bool useCurrentFilePosition = (ByteOffset == nullptr);
	if (!useCurrentFilePosition && *ByteOffset == FILE_USE_FILE_POINTER_POSITION) {
		useCurrentFilePosition = true;
	}

	std::optional<off64_t> offset;
	if (!useCurrentFilePosition) {
		offset = static_cast<off64_t>(*ByteOffset);
	}

	if (useOverlapped && useCurrentFilePosition) {
		IoStatusBlock->Status = STATUS_INVALID_PARAMETER;
		IoStatusBlock->Information = 0;
		return STATUS_INVALID_PARAMETER;
	}

	Pin<kernel32::EventObject> ev;
	if (Event) {
		ev = wibo::handles().getAs<kernel32::EventObject>(Event);
		if (!ev) {
			IoStatusBlock->Status = STATUS_INVALID_HANDLE;
			IoStatusBlock->Information = 0;
			return STATUS_INVALID_HANDLE;
		}
		ev->reset();
	}

	bool updateFilePointer = !useOverlapped;
	auto io = files::read(file.get(), Buffer, Length, offset, updateFilePointer);
	NTSTATUS status = STATUS_SUCCESS;
	if (io.unixError != 0) {
		status = wibo::statusFromErrno(io.unixError);
	} else if (io.reachedEnd && io.bytesTransferred == 0) {
		status = file->isPipe ? STATUS_PIPE_BROKEN : STATUS_END_OF_FILE;
	}

	IoStatusBlock->Status = status;
	IoStatusBlock->Information = static_cast<ULONG_PTR>(io.bytesTransferred);

	if (ev && (status == STATUS_SUCCESS || status == STATUS_END_OF_FILE)) {
		ev->set();
	}

	DEBUG_LOG("-> 0x%x\n", status);
	return status;
}

NTSTATUS WIN_FUNC NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
										  PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
	HOST_CONTEXT_GUARD();
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
	HOST_CONTEXT_GUARD();
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

NTSTATUS WIN_FUNC RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("RtlGetVersion(%p) ", lpVersionInformation);
	if (!lpVersionInformation) {
		DEBUG_LOG("-> 0x%x\n", STATUS_INVALID_PARAMETER);
		return STATUS_INVALID_PARAMETER;
	}

	ULONG size = lpVersionInformation->dwOSVersionInfoSize;
	if (size < sizeof(RTL_OSVERSIONINFOW)) {
		DEBUG_LOG("-> 0x%x\n", STATUS_INVALID_PARAMETER);
		return STATUS_INVALID_PARAMETER;
	}

	std::memset(lpVersionInformation, 0, static_cast<size_t>(size));
	lpVersionInformation->dwOSVersionInfoSize = size;
	lpVersionInformation->dwMajorVersion = kOsMajorVersion;
	lpVersionInformation->dwMinorVersion = kOsMinorVersion;
	lpVersionInformation->dwBuildNumber = kOsBuildNumber;
	lpVersionInformation->dwPlatformId = kOsPlatformId;

	if (size >= sizeof(RTL_OSVERSIONINFOEXW)) {
		auto extended = reinterpret_cast<PRTL_OSVERSIONINFOEXW>(lpVersionInformation);
		extended->wProductType = kProductTypeWorkstation;
	}

	DEBUG_LOG("-> 0x%x\n", STATUS_SUCCESS);
	return STATUS_SUCCESS;
}

NTSTATUS WIN_FUNC NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
											PVOID ProcessInformation, ULONG ProcessInformationLength,
											PULONG ReturnLength) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("NtQueryInformationProcess(%p, %u, %p, %u, %p) ", ProcessHandle, ProcessInformationClass,
			  ProcessInformation, ProcessInformationLength, ReturnLength);
	if (!ProcessInformation) {
		DEBUG_LOG("-> 0x%x\n", STATUS_INVALID_PARAMETER);
		return STATUS_INVALID_PARAMETER;
	}

	ProcessHandleDetails details{};
	if (!resolveProcessDetails(ProcessHandle, details)) {
		DEBUG_LOG("-> 0x%x\n", STATUS_INVALID_HANDLE);
		return STATUS_INVALID_HANDLE;
	}

	switch (ProcessInformationClass) {
	case ProcessBasicInformation: {
		size_t required = sizeof(PROCESS_BASIC_INFORMATION);
		if (ReturnLength) {
			*ReturnLength = static_cast<ULONG>(required);
		}
		if (ProcessInformationLength < required) {
			DEBUG_LOG("-> 0x%x\n", STATUS_INFO_LENGTH_MISMATCH);
			return STATUS_INFO_LENGTH_MISMATCH;
		}

		auto *info = reinterpret_cast<PROCESS_BASIC_INFORMATION *>(ProcessInformation);
		std::memset(info, 0, sizeof(*info));
		info->ExitStatus = static_cast<NTSTATUS>(details.exitCode);
		info->PebBaseAddress = details.peb;
		DWORD_PTR processMask = 0;
		DWORD_PTR systemMask = 0;
		if (kernel32::GetProcessAffinityMask(ProcessHandle, &processMask, &systemMask)) {
			info->AffinityMask = static_cast<ULONG_PTR>(processMask == 0 ? 1 : processMask);
		} else {
			info->AffinityMask = 1;
		}
		info->BasePriority = kDefaultBasePriority;
		info->UniqueProcessId = static_cast<ULONG_PTR>(details.pid);
		if (details.isCurrentProcess) {
			info->InheritedFromUniqueProcessId = static_cast<ULONG_PTR>(getppid());
		} else {
			info->InheritedFromUniqueProcessId = static_cast<ULONG_PTR>(getpid());
		}
		DEBUG_LOG("-> 0x%x\n", STATUS_SUCCESS);
		return STATUS_SUCCESS;
	}
	case ProcessWow64Information: {
		size_t required = sizeof(ULONG_PTR);
		if (ReturnLength) {
			*ReturnLength = static_cast<ULONG>(required);
		}
		if (ProcessInformationLength < required) {
			DEBUG_LOG("-> 0x%x\n", STATUS_INFO_LENGTH_MISMATCH);
			return STATUS_INFO_LENGTH_MISMATCH;
		}
		auto *value = reinterpret_cast<ULONG_PTR *>(ProcessInformation);
		*value = 0;
		DEBUG_LOG("-> 0x%x\n", STATUS_SUCCESS);
		return STATUS_SUCCESS;
	}
	case ProcessImageFileName: {
		size_t minimum = sizeof(UNICODE_STRING);
		if (ProcessInformationLength < minimum) {
			if (ReturnLength) {
				*ReturnLength = static_cast<ULONG>(minimum);
			}
			DEBUG_LOG("-> 0x%x\n", STATUS_INFO_LENGTH_MISMATCH);
			return STATUS_INFO_LENGTH_MISMATCH;
		}

		std::string imagePath = windowsImagePathFor(details);
		DEBUG_LOG("  NtQueryInformationProcess image path: %s\n", imagePath.c_str());
		auto widePath = stringToWideString(imagePath.c_str());
		size_t stringBytes = widePath.size() * sizeof(uint16_t);
		size_t required = sizeof(UNICODE_STRING) + stringBytes;
		if (ReturnLength) {
			*ReturnLength = static_cast<ULONG>(required);
		}
		if (ProcessInformationLength < required) {
			DEBUG_LOG("-> 0x%x\n", STATUS_INFO_LENGTH_MISMATCH);
			return STATUS_INFO_LENGTH_MISMATCH;
		}

		auto *unicode = reinterpret_cast<UNICODE_STRING *>(ProcessInformation);
		auto *buffer =
			reinterpret_cast<uint16_t *>(reinterpret_cast<uint8_t *>(ProcessInformation) + sizeof(UNICODE_STRING));
		std::memcpy(buffer, widePath.data(), stringBytes);
		size_t characterCount = widePath.empty() ? 0 : widePath.size() - 1;
		unicode->Length = static_cast<unsigned short>(characterCount * sizeof(uint16_t));
		unicode->MaximumLength = static_cast<unsigned short>(widePath.size() * sizeof(uint16_t));
		unicode->Buffer = buffer;
		DEBUG_LOG("-> 0x%x\n", STATUS_SUCCESS);
		return STATUS_SUCCESS;
	}
	default:
		DEBUG_LOG("-> 0x%x\n", STATUS_INVALID_INFO_CLASS);
		return STATUS_INVALID_INFO_CLASS;
	}
}

} // namespace ntdll

static void *resolveByName(const char *name) {
	if (strcmp(name, "NtReadFile") == 0)
		return (void *)ntdll::NtReadFile;
	if (strcmp(name, "NtAllocateVirtualMemory") == 0)
		return (void *)ntdll::NtAllocateVirtualMemory;
	if (strcmp(name, "NtProtectVirtualMemory") == 0)
		return (void *)ntdll::NtProtectVirtualMemory;
	if (strcmp(name, "RtlGetVersion") == 0)
		return (void *)ntdll::RtlGetVersion;
	if (strcmp(name, "NtQueryInformationProcess") == 0)
		return (void *)ntdll::NtQueryInformationProcess;
	return nullptr;
}

wibo::ModuleStub lib_ntdll = {
	(const char *[]){
		"ntdll",
		nullptr,
	},
	resolveByName,
	nullptr,
};
