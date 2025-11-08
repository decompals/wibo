#include "ntdll.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "files.h"
#include "handles.h"
#include "heap.h"
#include "kernel32/fileapi.h"
#include "kernel32/internal.h"
#include "kernel32/minwinbase.h"
#include "kernel32/processthreadsapi.h"
#include "modules.h"
#include "processes.h"
#include "strutil.h"
#include "types.h"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <limits>
#include <sys/stat.h>
#include <unistd.h>

#include <optional>

namespace {

struct PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	GUEST_PTR PebBaseAddress;
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

constexpr ULONGLONG kHundredNanosecondsPerSecond = 10'000'000ULL;
constexpr ULONGLONG kUnixEpochAsFileTime = 116'444'736'000'000'000ULL;

struct StatFetchResult {
	bool ok = false;
	int err = 0;
};

#if defined(__APPLE__)
timespec accessTimespec(const struct stat &st) { return st.st_atimespec; }
timespec modifyTimespec(const struct stat &st) { return st.st_mtimespec; }
timespec changeTimespec(const struct stat &st) { return st.st_ctimespec; }
#elif defined(__linux__)
timespec accessTimespec(const struct stat &st) { return st.st_atim; }
timespec modifyTimespec(const struct stat &st) { return st.st_mtim; }
timespec changeTimespec(const struct stat &st) { return st.st_ctim; }
#else
timespec accessTimespec(const struct stat &st) { return timespec{.tv_sec = st.st_atime, .tv_nsec = 0}; }
timespec modifyTimespec(const struct stat &st) { return timespec{.tv_sec = st.st_mtime, .tv_nsec = 0}; }
timespec changeTimespec(const struct stat &st) { return timespec{.tv_sec = st.st_ctime, .tv_nsec = 0}; }
#endif

LONGLONG timespecToFileTime(const timespec &ts) {
#if defined(__SIZEOF_INT128__)
	__int128 ticks = static_cast<__int128>(ts.tv_sec) * static_cast<__int128>(kHundredNanosecondsPerSecond);
	ticks += static_cast<__int128>(ts.tv_nsec / 100);
	ticks += static_cast<__int128>(kUnixEpochAsFileTime);
	if (ticks < 0) {
		return 0;
	}
	if (ticks > static_cast<__int128>(std::numeric_limits<LONGLONG>::max())) {
		return std::numeric_limits<LONGLONG>::max();
	}
	return static_cast<LONGLONG>(ticks);
#else
	long double ticks = static_cast<long double>(ts.tv_sec) * static_cast<long double>(kHundredNanosecondsPerSecond);
	ticks += static_cast<long double>(ts.tv_nsec) / 100.0L;
	ticks += static_cast<long double>(kUnixEpochAsFileTime);
	if (ticks < 0.0L) {
		return 0;
	}
	if (ticks > static_cast<long double>(std::numeric_limits<LONGLONG>::max())) {
		return std::numeric_limits<LONGLONG>::max();
	}
	return static_cast<LONGLONG>(ticks);
#endif
}

DWORD buildFileAttributes(const struct stat &st) {
	DWORD attributes = 0;
	mode_t mode = st.st_mode;
	if (S_ISDIR(mode)) {
		attributes |= FILE_ATTRIBUTE_DIRECTORY;
	}
	if (S_ISREG(mode)) {
		attributes |= FILE_ATTRIBUTE_ARCHIVE;
	}
	if ((mode & S_IWUSR) == 0) {
		attributes |= FILE_ATTRIBUTE_READONLY;
	}
	if (attributes == 0) {
		attributes = FILE_ATTRIBUTE_NORMAL;
	}
	return attributes;
}

StatFetchResult fetchStat(kernel32::FsObject *fs, struct stat &st) {
	if (!fs) {
		return {};
	}
	if (fs->valid()) {
		if (fstat(fs->fd, &st) == 0) {
			return StatFetchResult{.ok = true, .err = 0};
		}
		if (errno != EBADF) {
			return StatFetchResult{.ok = false, .err = errno};
		}
	}
	if (!fs->canonicalPath.empty()) {
		if (stat(fs->canonicalPath.c_str(), &st) == 0) {
			return StatFetchResult{.ok = true, .err = 0};
		}
		return StatFetchResult{.ok = false, .err = errno};
	}
	return StatFetchResult{};
}

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
	return {};
}

} // namespace

namespace kernel32 {
BOOL WINAPI SetEvent(HANDLE hEvent);
BOOL WINAPI ResetEvent(HANDLE hEvent);
} // namespace kernel32

namespace ntdll {

constexpr LARGE_INTEGER FILE_WRITE_TO_END_OF_FILE = {.QuadPart = -1};
constexpr LARGE_INTEGER FILE_USE_FILE_POINTER_POSITION = {.QuadPart = -2};

PVOID CDECL memset(PVOID dest, int ch, SIZE_T count) {
	VERBOSE_LOG("ntdll::memset(%p, %i, %zu)\n", dest, ch, count);
	return std::memset(dest, ch, count);
}

NTSTATUS WINAPI NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
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
	if (!useCurrentFilePosition && ByteOffset->QuadPart == FILE_USE_FILE_POINTER_POSITION.QuadPart) {
		useCurrentFilePosition = true;
	}

	std::optional<off_t> offset;
	if (!useCurrentFilePosition) {
		offset = static_cast<off_t>(ByteOffset->QuadPart);
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

NTSTATUS WINAPI NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
							PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
							PULONG Key) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("NtWriteFile(%p, %p, %p, %p, %p, %p, %u, %p, %p) ", FileHandle, Event, ApcRoutine, ApcContext,
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
		return STATUS_INVALID_HANDLE;
	}

	bool useOverlapped = file->overlapped;
	bool useCurrentFilePosition = (ByteOffset == nullptr);
	bool writeToEndOfFile = false;
	if (ByteOffset) {
		if (ByteOffset->QuadPart == FILE_USE_FILE_POINTER_POSITION.QuadPart) {
			useCurrentFilePosition = true;
		} else if (ByteOffset->QuadPart == FILE_WRITE_TO_END_OF_FILE.QuadPart) {
			writeToEndOfFile = true;
		}
	}

	std::optional<off_t> offset;
	if (!useCurrentFilePosition && !writeToEndOfFile) {
		offset = static_cast<off_t>(ByteOffset->QuadPart);
	}

	if (useOverlapped && useCurrentFilePosition) {
		IoStatusBlock->Status = STATUS_INVALID_PARAMETER;
		return STATUS_INVALID_PARAMETER;
	}

	Pin<kernel32::EventObject> ev;
	if (Event) {
		ev = wibo::handles().getAs<kernel32::EventObject>(Event);
		if (!ev) {
			IoStatusBlock->Status = STATUS_INVALID_HANDLE;
			return STATUS_INVALID_HANDLE;
		}
		ev->reset();
	}

	bool updateFilePointer = file->isPipe ? true : !useOverlapped;

	if (writeToEndOfFile && !offset.has_value()) {
		if (!file->isPipe) {
			struct stat st{};
			if (fstat(file->fd, &st) != 0) {
				int err = errno ? errno : EIO;
				NTSTATUS status = wibo::statusFromErrno(err);
				IoStatusBlock->Status = status;
				return status;
			}
			offset = static_cast<off_t>(st.st_size);
		}
	}

	auto io = files::write(file.get(), Buffer, static_cast<size_t>(Length), offset, updateFilePointer);
	NTSTATUS status = STATUS_SUCCESS;
	if (io.unixError != 0) {
		status = wibo::statusFromErrno(io.unixError);
	}

	IoStatusBlock->Status = status;
	IoStatusBlock->Information = static_cast<ULONG_PTR>(io.bytesTransferred);

	if (ev && status == STATUS_SUCCESS) {
		ev->set();
	}

	DEBUG_LOG("-> 0x%x\n", status);
	return status;
}

NTSTATUS WINAPI NtAllocateVirtualMemory(HANDLE ProcessHandle, guest_ptr<> *BaseAddress, ULONG_PTR ZeroBits,
										PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("NtAllocateVirtualMemory(%p, %p, %lu, %p, %lu, %lu) ", ProcessHandle, BaseAddress, ZeroBits, RegionSize,
			  AllocationType, Protect);
	if (ProcessHandle != (HANDLE)-1) {
		DEBUG_LOG("-> 0x%x\n", STATUS_INVALID_HANDLE);
		return STATUS_INVALID_HANDLE;
	}
	if (ZeroBits != 0 || BaseAddress == nullptr || RegionSize == nullptr) {
		DEBUG_LOG("-> 0x%x\n", STATUS_INVALID_PARAMETER);
		return STATUS_INVALID_PARAMETER;
	}

	void *baseAddress = BaseAddress->get();
	size_t regionSize = static_cast<size_t>(*RegionSize);
	wibo::heap::VmStatus vmStatus = wibo::heap::virtualAlloc(
		&baseAddress, &regionSize, static_cast<DWORD>(AllocationType), static_cast<DWORD>(Protect));
	if (vmStatus != wibo::heap::VmStatus::Success) {
		NTSTATUS status = wibo::heap::ntStatusFromVmStatus(vmStatus);
		DEBUG_LOG("-> 0x%x\n", status);
		return status;
	}

	*BaseAddress = baseAddress;
	*RegionSize = static_cast<SIZE_T>(regionSize);

	DEBUG_LOG("-> 0x%x\n", STATUS_SUCCESS);
	return STATUS_SUCCESS;
}

NTSTATUS WINAPI NtProtectVirtualMemory(HANDLE ProcessHandle, guest_ptr<> *BaseAddress, PSIZE_T NumberOfBytesToProtect,
									   ULONG NewAccessProtection, PULONG OldAccessProtection) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("NtProtectVirtualMemory(%p, %p, %p, %lu, %p) ", ProcessHandle, BaseAddress, NumberOfBytesToProtect,
			  NewAccessProtection, OldAccessProtection);
	if (ProcessHandle != (HANDLE)-1) {
		DEBUG_LOG("-> 0x%x\n", STATUS_INVALID_HANDLE);
		return STATUS_INVALID_HANDLE;
	}
	if (BaseAddress == nullptr || NumberOfBytesToProtect == nullptr) {
		DEBUG_LOG("-> 0x%x\n", STATUS_INVALID_PARAMETER);
		return STATUS_INVALID_PARAMETER;
	}

	void *base = BaseAddress->get();
	size_t length = static_cast<size_t>(*NumberOfBytesToProtect);
	wibo::heap::VmStatus vmStatus =
		wibo::heap::virtualProtect(base, length, static_cast<DWORD>(NewAccessProtection), OldAccessProtection);
	if (vmStatus != wibo::heap::VmStatus::Success) {
		NTSTATUS status = wibo::heap::ntStatusFromVmStatus(vmStatus);
		DEBUG_LOG("-> 0x%x\n", status);
		return status;
	}

	DEBUG_LOG("-> 0x%x\n", STATUS_SUCCESS);
	return STATUS_SUCCESS;
}

NTSTATUS WINAPI NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
									   ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("NtQueryInformationFile(%p, %p, %p, %u, %u) ", FileHandle, IoStatusBlock, FileInformation, Length,
			  static_cast<unsigned>(FileInformationClass));

	if (!IoStatusBlock) {
		DEBUG_LOG("-> 0x%x\n", STATUS_ACCESS_VIOLATION);
		return STATUS_ACCESS_VIOLATION;
	}

	IoStatusBlock->Information = 0;

	if (Length != 0 && !FileInformation) {
		IoStatusBlock->Status = STATUS_ACCESS_VIOLATION;
		DEBUG_LOG("-> 0x%x\n", STATUS_ACCESS_VIOLATION);
		return STATUS_ACCESS_VIOLATION;
	}

	if (reinterpret_cast<int32_t>(FileHandle) < 0) {
		IoStatusBlock->Status = STATUS_OBJECT_TYPE_MISMATCH;
		DEBUG_LOG("-> 0x%x\n", STATUS_OBJECT_TYPE_MISMATCH);
		return STATUS_OBJECT_TYPE_MISMATCH;
	}

	auto obj = wibo::handles().getAs<kernel32::FsObject>(FileHandle);
	if (!obj || !obj->valid()) {
		IoStatusBlock->Status = STATUS_INVALID_HANDLE;
		DEBUG_LOG("-> 0x%x\n", STATUS_INVALID_HANDLE);
		return STATUS_INVALID_HANDLE;
	}

	std::lock_guard lock(obj->m);
	NTSTATUS status = STATUS_SUCCESS;

	switch (FileInformationClass) {
	case FileBasicInformation: {
		if (Length < sizeof(FILE_BASIC_INFORMATION)) {
			status = STATUS_INFO_LENGTH_MISMATCH;
			break;
		}
		struct stat st{};
		StatFetchResult statRes = fetchStat(obj.get(), st);
		if (!statRes.ok) {
			status = wibo::statusFromErrno(statRes.err != 0 ? statRes.err : EINVAL);
			break;
		}
		auto info = reinterpret_cast<PFILE_BASIC_INFORMATION>(FileInformation);
		info->CreationTime.QuadPart = timespecToFileTime(changeTimespec(st));
		info->LastAccessTime.QuadPart = timespecToFileTime(accessTimespec(st));
		info->LastWriteTime.QuadPart = timespecToFileTime(modifyTimespec(st));
		info->ChangeTime.QuadPart = timespecToFileTime(changeTimespec(st));
		info->FileAttributes = buildFileAttributes(st);
		IoStatusBlock->Information = sizeof(FILE_BASIC_INFORMATION);
		break;
	}
	case FileStandardInformation: {
		if (Length < sizeof(FILE_STANDARD_INFORMATION)) {
			status = STATUS_INFO_LENGTH_MISMATCH;
			break;
		}
		struct stat st{};
		StatFetchResult statRes = fetchStat(obj.get(), st);
		if (!statRes.ok) {
			status = wibo::statusFromErrno(statRes.err != 0 ? statRes.err : EINVAL);
			break;
		}
		auto info = reinterpret_cast<PFILE_STANDARD_INFORMATION>(FileInformation);
		unsigned long long allocation = static_cast<unsigned long long>(st.st_blocks) * 512ULL;
		info->AllocationSize.QuadPart = static_cast<LONGLONG>(allocation);
		info->EndOfFile.QuadPart = static_cast<LONGLONG>(st.st_size);
		info->NumberOfLinks = static_cast<ULONG>(st.st_nlink);
		info->DeletePending = obj->deletePending ? TRUE : FALSE;
		info->Directory = S_ISDIR(st.st_mode) ? TRUE : FALSE;
		info->Reserved = 0;
		IoStatusBlock->Information = sizeof(FILE_STANDARD_INFORMATION);
		break;
	}
	case FilePositionInformation: {
		auto file = std::move(obj).downcast<kernel32::FileObject>();
		if (!file) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}
		if (Length < sizeof(FILE_POSITION_INFORMATION)) {
			status = STATUS_INFO_LENGTH_MISMATCH;
			break;
		}
		auto info = reinterpret_cast<PFILE_POSITION_INFORMATION>(FileInformation);
		info->CurrentByteOffset.QuadPart = static_cast<LONGLONG>(file->filePos);
		IoStatusBlock->Information = sizeof(FILE_POSITION_INFORMATION);
		break;
	}
	case FileNameInformation: {
		if (Length < sizeof(ULONG)) {
			status = STATUS_INFO_LENGTH_MISMATCH;
			break;
		}
		std::string windowsPath;
		if (!obj->canonicalPath.empty()) {
			windowsPath = files::pathToWindows(obj->canonicalPath);
		}
		std::string volumeRelative;
		if (!windowsPath.empty()) {
			if (windowsPath.size() >= 2 && windowsPath[1] == ':') {
				volumeRelative = windowsPath.substr(2);
				if (volumeRelative.empty() || volumeRelative.front() != '\\') {
					volumeRelative.insert(volumeRelative.begin(), '\\');
				}
			} else if (!windowsPath.empty() && windowsPath.front() != '\\') {
				volumeRelative = "\\" + windowsPath;
			} else {
				volumeRelative = windowsPath;
			}
		}
		auto info = reinterpret_cast<PFILE_NAME_INFORMATION>(FileInformation);
		auto wide = stringToWideString(volumeRelative.c_str(), volumeRelative.size());
		size_t charCount = wide.empty() ? 0 : wstrlen(wide.data());
		size_t bytesRequired = charCount * sizeof(uint16_t);
		if (Length < sizeof(ULONG) + bytesRequired) {
			info->FileNameLength = static_cast<ULONG>(bytesRequired);
			status = STATUS_INFO_LENGTH_MISMATCH;
			break;
		}
		info->FileNameLength = static_cast<ULONG>(bytesRequired);
		if (bytesRequired > 0) {
			std::memcpy(info->FileName, wide.data(), bytesRequired);
		}
		IoStatusBlock->Information = static_cast<ULONG>(sizeof(ULONG) + bytesRequired);
		break;
	}
	default:
		DEBUG_LOG("FIXME: NtQueryInformationFile: Unsupported info class");
		status = STATUS_INVALID_INFO_CLASS;
		break;
	}

	IoStatusBlock->Status = status;
	DEBUG_LOG("-> 0x%x\n", status);
	return status;
}

NTSTATUS WINAPI NtQuerySystemTime(PLARGE_INTEGER SystemTime) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("NtQuerySystemTime(%p) ", SystemTime);
	if (!SystemTime) {
		DEBUG_LOG("-> 0x%x\n", STATUS_ACCESS_VIOLATION);
		return STATUS_ACCESS_VIOLATION;
	}

	using HundredNanoseconds = std::chrono::duration<long long, std::ratio<1, 10000000>>;
	auto now = std::chrono::system_clock::now().time_since_epoch();
	auto sinceUnix = std::chrono::duration_cast<HundredNanoseconds>(now).count();
	ULONGLONG fileTime = kUnixEpochAsFileTime + static_cast<ULONGLONG>(sinceUnix);
	SystemTime->QuadPart = static_cast<LONGLONG>(fileTime);

	DEBUG_LOG("-> 0x%x\n", STATUS_SUCCESS);
	return STATUS_SUCCESS;
}

BOOLEAN WINAPI RtlTimeToSecondsSince1970(PLARGE_INTEGER Time, PULONG ElapsedSeconds) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("RtlTimeToSecondsSince1970(%p, %p) ", Time, ElapsedSeconds);
	if (!Time || !ElapsedSeconds) {
		DEBUG_LOG("-> %u\n", FALSE);
		return FALSE;
	}

	LONGLONG fileTimeSigned = Time->QuadPart;
	if (fileTimeSigned < 0) {
		DEBUG_LOG("-> %u\n", FALSE);
		return FALSE;
	}

	ULONGLONG fileTime = static_cast<ULONGLONG>(fileTimeSigned);
	if (fileTime < kUnixEpochAsFileTime) {
		DEBUG_LOG("-> %u\n", FALSE);
		return FALSE;
	}

	ULONGLONG delta = fileTime - kUnixEpochAsFileTime;
	ULONGLONG seconds = delta / kHundredNanosecondsPerSecond;
	if (seconds > 0xFFFFFFFFULL) {
		DEBUG_LOG("-> %u\n", FALSE);
		return FALSE;
	}

	*ElapsedSeconds = static_cast<ULONG>(seconds);
	DEBUG_LOG("-> %u\n", TRUE);
	return TRUE;
}

VOID WINAPI RtlInitializeBitMap(PRTL_BITMAP BitMapHeader, PULONG BitMapBuffer, ULONG SizeOfBitMap) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("RtlInitializeBitMap(%p, %p, %u)\n", BitMapHeader, BitMapBuffer, SizeOfBitMap);
	if (!BitMapHeader) {
		return;
	}

	BitMapHeader->SizeOfBitMap = SizeOfBitMap;
	BitMapHeader->Buffer = BitMapBuffer;
}

VOID WINAPI RtlSetBits(PRTL_BITMAP BitMapHeader, ULONG StartingIndex, ULONG NumberToSet) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("RtlSetBits(%p, %u, %u)\n", BitMapHeader, StartingIndex, NumberToSet);
	if (!BitMapHeader || !BitMapHeader->Buffer || NumberToSet == 0) {
		return;
	}

	ULONG size = BitMapHeader->SizeOfBitMap;
	if (StartingIndex >= size) {
		return;
	}

	ULONG available = size - StartingIndex;
	if (NumberToSet > available) {
		NumberToSet = available;
	}

	for (ULONG i = 0; i < NumberToSet; ++i) {
		ULONG bitIndex = StartingIndex + i;
		ULONG wordIndex = bitIndex / 32;
		ULONG offset = bitIndex % 32;
		BitMapHeader->Buffer[wordIndex] |= (1u << offset);
	}
}

BOOLEAN WINAPI RtlAreBitsSet(PRTL_BITMAP BitMapHeader, ULONG StartingIndex, ULONG Length) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("RtlAreBitsSet(%p, %u, %u) ", BitMapHeader, StartingIndex, Length);
	if (!BitMapHeader || !BitMapHeader->Buffer || Length == 0) {
		DEBUG_LOG("-> %u\n", FALSE);
		return FALSE;
	}

	ULONG size = BitMapHeader->SizeOfBitMap;
	if (StartingIndex >= size || Length > size - StartingIndex) {
		DEBUG_LOG("-> %u\n", FALSE);
		return FALSE;
	}

	for (ULONG i = 0; i < Length; ++i) {
		ULONG bitIndex = StartingIndex + i;
		ULONG wordIndex = bitIndex / 32;
		ULONG offset = bitIndex % 32;
		if ((BitMapHeader->Buffer[wordIndex] & (1u << offset)) == 0) {
			DEBUG_LOG("-> %u\n", FALSE);
			return FALSE;
		}
	}

	DEBUG_LOG("-> %u\n", TRUE);
	return TRUE;
}

BOOLEAN WINAPI RtlAreBitsClear(PRTL_BITMAP BitMapHeader, ULONG StartingIndex, ULONG Length) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("RtlAreBitsClear(%p, %u, %u) ", BitMapHeader, StartingIndex, Length);
	if (!BitMapHeader || !BitMapHeader->Buffer || Length == 0) {
		DEBUG_LOG("-> %u\n", FALSE);
		return FALSE;
	}

	ULONG size = BitMapHeader->SizeOfBitMap;
	if (StartingIndex >= size || Length > size - StartingIndex) {
		DEBUG_LOG("-> %u\n", FALSE);
		return FALSE;
	}

	for (ULONG i = 0; i < Length; ++i) {
		ULONG bitIndex = StartingIndex + i;
		ULONG wordIndex = bitIndex / 32;
		ULONG offset = bitIndex % 32;
		if ((BitMapHeader->Buffer[wordIndex] & (1u << offset)) != 0) {
			DEBUG_LOG("-> %u\n", FALSE);
			return FALSE;
		}
	}

	DEBUG_LOG("-> %u\n", TRUE);
	return TRUE;
}

NTSTATUS WINAPI RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation) {
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

NTSTATUS WINAPI NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
										  PVOID ProcessInformation, ULONG ProcessInformationLength,
										  PULONG ReturnLength) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("NtQueryInformationProcess(%d, %u, %p, %u, %p) ", ProcessHandle, ProcessInformationClass,
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
		info->PebBaseAddress = toGuestPtr(details.peb);
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
		unicode->Buffer = toGuestPtr(buffer);
		DEBUG_LOG("-> 0x%x\n", STATUS_SUCCESS);
		return STATUS_SUCCESS;
	}
	default:
		DEBUG_LOG("-> 0x%x\n", STATUS_INVALID_INFO_CLASS);
		return STATUS_INVALID_INFO_CLASS;
	}
}

} // namespace ntdll

#include "ntdll_trampolines.h"

extern const wibo::ModuleStub lib_ntdll = {
	(const char *[]){
		"ntdll",
		nullptr,
	},
	ntdllThunkByName,
	nullptr,
};
