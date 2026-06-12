#include "msvc_compat_ntdll.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "files.h"
#include "handles.h"
#include "kernel32/fileapi.h"
#include "kernel32/handleapi.h"
#include "kernel32/heapapi.h"
#include "kernel32/internal.h"
#include "strutil.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <map>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace {

constexpr NTSTATUS STATUS_SUCCESS_ = 0x00000000;
constexpr NTSTATUS STATUS_NO_MORE_FILES_ = 0x80000006;
constexpr NTSTATUS STATUS_INVALID_HANDLE_ = 0xC0000008;
constexpr NTSTATUS STATUS_INVALID_PARAMETER_ = 0xC000000D;
constexpr NTSTATUS STATUS_BUFFER_OVERFLOW_ = 0x80000005;

uint64_t unixToFiletime(time_t sec) {
	return (static_cast<uint64_t>(sec) + 11644473600ULL) * 10000000ULL;
}

bool wildcardMatchCI(const std::string &name, const std::string &pat) {
	// Case-insensitive '*'/'?' match. '<' '>' '"' DOS wildcards not handled.
	size_t n = 0, p = 0, star = std::string::npos, mark = 0;
	auto low = [](char c) { return (c >= 'A' && c <= 'Z') ? char(c + 32) : c; };
	while (n < name.size()) {
		if (p < pat.size() && (pat[p] == '?' || low(pat[p]) == low(name[n]))) {
			++n; ++p;
		} else if (p < pat.size() && pat[p] == '*') {
			star = p++; mark = n;
		} else if (star != std::string::npos) {
			p = star + 1; n = ++mark;
		} else {
			return false;
		}
	}
	while (p < pat.size() && pat[p] == '*') ++p;
	return p == pat.size();
}

struct DirEnum {
	std::vector<std::string> names;
	size_t pos = 0;
};
std::mutex g_dirMutex;
std::map<HANDLE, DirEnum> g_dirEnum;

void putU32(uint8_t *b, size_t off, uint32_t v) { std::memcpy(b + off, &v, 4); }
void putU64(uint8_t *b, size_t off, uint64_t v) { std::memcpy(b + off, &v, 8); }

// FileName field offset for the directory-info classes cl is likely to request.
size_t fileNameOffsetForClass(ULONG cls) {
	switch (cls) {
	case 1: return 64;   // FileDirectoryInformation
	case 2: return 68;   // FileFullDirectoryInformation
	case 3: return 94;   // FileBothDirectoryInformation
	case 12: return 12;  // FileNamesInformation
	case 37: return 104; // FileIdBothDirectoryInformation
	case 38: return 80;  // FileIdFullDirectoryInformation
	default: return 94;
	}
}

} // namespace

namespace ntdll {

BOOLEAN WINAPI RtlCreateUnicodeString(UNICODE_STRING *DestinationString, const WCHAR *SourceString) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("RtlCreateUnicodeString(%p, %p)\n", (void *)DestinationString, (const void *)SourceString);
	if (!DestinationString) {
		return FALSE;
	}
	size_t chars = SourceString ? wstrlen(SourceString) : 0;
	size_t bytes = (chars + 1) * sizeof(uint16_t);
	void *buf = kernel32::HeapAlloc(kernel32::GetProcessHeap(), 0, bytes);
	if (!buf) {
		return FALSE;
	}
	if (SourceString) {
		std::memcpy(buf, SourceString, bytes);
	} else {
		*static_cast<uint16_t *>(buf) = 0;
	}
	DestinationString->Length = static_cast<USHORT>(chars * sizeof(uint16_t));
	DestinationString->MaximumLength = static_cast<USHORT>(bytes);
	DestinationString->Buffer = toGuestPtr(buf);
	return TRUE;
}

VOID WINAPI RtlFreeUnicodeString(UNICODE_STRING *UnicodeString) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("RtlFreeUnicodeString(%p)\n", (void *)UnicodeString);
	if (UnicodeString && UnicodeString->Buffer) {
		kernel32::HeapFree(kernel32::GetProcessHeap(), 0, fromGuestPtr<void>(UnicodeString->Buffer));
		UnicodeString->Buffer = GUEST_NULL;
		UnicodeString->Length = 0;
		UnicodeString->MaximumLength = 0;
	}
}

NTSTATUS WINAPI NtClose(HANDLE Handle) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("NtClose(%p)\n", Handle);
	{
		std::lock_guard<std::mutex> lk(g_dirMutex);
		g_dirEnum.erase(Handle);
	}
	return kernel32::CloseHandle(Handle) ? STATUS_SUCCESS_ : STATUS_INVALID_HANDLE_;
}

NTSTATUS WINAPI NtCreateFile(HANDLE *FileHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes,
							 PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
							 ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer,
							 ULONG EaLength) {
	HOST_CONTEXT_GUARD();
	(void)AllocationSize; (void)EaBuffer; (void)EaLength;
	if (!FileHandle || !ObjectAttributes || !ObjectAttributes->ObjectName) {
		return STATUS_INVALID_PARAMETER_;
	}
	UNICODE_STRING *name = ObjectAttributes->ObjectName;
	const uint16_t *buf = fromGuestPtr<uint16_t>(name->Buffer);
	size_t n = buf ? name->Length / sizeof(uint16_t) : 0;
	if (n >= 4 && buf[0] == '\\' && buf[1] == '?' && buf[2] == '?' && buf[3] == '\\') {
		buf += 4;
		n -= 4;
	}
	std::vector<uint16_t> wname(buf, buf + n);
	wname.push_back(0);
	DEBUG_LOG("NtCreateFile('%s' access=0x%x disp=%u share=%u opts=0x%x)\n",
			  wideStringToString(reinterpret_cast<LPCWSTR>(wname.data())).c_str(), DesiredAccess, CreateDisposition,
			  ShareAccess, CreateOptions);

	DWORD disp;
	switch (CreateDisposition) {
	case 0: disp = 2; break; // FILE_SUPERSEDE    -> CREATE_ALWAYS
	case 1: disp = 3; break; // FILE_OPEN         -> OPEN_EXISTING
	case 2: disp = 1; break; // FILE_CREATE       -> CREATE_NEW
	case 3: disp = 4; break; // FILE_OPEN_IF      -> OPEN_ALWAYS
	case 4: disp = 5; break; // FILE_OVERWRITE    -> TRUNCATE_EXISTING
	case 5: disp = 2; break; // FILE_OVERWRITE_IF -> CREATE_ALWAYS
	default: disp = 3; break;
	}
	DWORD flags = FileAttributes ? FileAttributes : 0x80; // FILE_ATTRIBUTE_NORMAL
	if (CreateOptions & 0x00001000u) flags |= 0x04000000u; // FILE_DELETE_ON_CLOSE
	if (CreateOptions & 0x00000001u) flags |= 0x02000000u; // FILE_DIRECTORY_FILE -> BACKUP_SEMANTICS

	HANDLE h = kernel32::CreateFileW(reinterpret_cast<LPCWSTR>(wname.data()), DesiredAccess, ShareAccess, nullptr, disp,
									 flags, NO_HANDLE);
	if (h == INVALID_HANDLE_VALUE) {
		DWORD e = kernel32::getLastError();
		NTSTATUS st = (e == ERROR_ACCESS_DENIED) ? 0xC0000022 : 0xC0000034;
		if (IoStatusBlock) { IoStatusBlock->Status = st; IoStatusBlock->Information = 0; }
		return st;
	}
	*FileHandle = h;
	if (IoStatusBlock) { IoStatusBlock->Status = STATUS_SUCCESS_; IoStatusBlock->Information = 1; } // FILE_OPENED
	return STATUS_SUCCESS_;
}

NTSTATUS WINAPI NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
									 PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
									 ULONG FileInformationClass, ULONG ReturnSingleEntry, UNICODE_STRING *FileName,
									 ULONG RestartScan) {
	HOST_CONTEXT_GUARD();
	(void)Event; (void)ApcRoutine; (void)ApcContext; (void)ReturnSingleEntry;
	auto fobj = wibo::handles().getAs<FileObject>(FileHandle);
	if (!fobj) {
		return STATUS_INVALID_HANDLE_;
	}
	std::string pattern = "*";
	if (FileName && FileName->Buffer && FileName->Length) {
		const uint16_t *pb = fromGuestPtr<uint16_t>(FileName->Buffer);
		std::vector<uint16_t> pw(pb, pb + FileName->Length / sizeof(uint16_t));
		pw.push_back(0);
		pattern = wideStringToString(reinterpret_cast<LPCWSTR>(pw.data()));
	}
	DEBUG_LOG("NtQueryDirectoryFile(class=%u pattern='%s' restart=%u dir='%s')\n", FileInformationClass,
			  pattern.c_str(), RestartScan, fobj->canonicalPath.c_str());

	std::lock_guard<std::mutex> lk(g_dirMutex);
	DirEnum &en = g_dirEnum[FileHandle];
	if (RestartScan || (en.names.empty() && en.pos == 0)) {
		en.names.clear();
		en.pos = 0;
		std::error_code ec;
		for (auto &de : std::filesystem::directory_iterator(fobj->canonicalPath, ec)) {
			std::string fn = de.path().filename().string();
			if (wildcardMatchCI(fn, pattern)) {
				en.names.push_back(fn);
			}
		}
		std::sort(en.names.begin(), en.names.end());
	}
	if (en.pos >= en.names.size()) {
		if (IoStatusBlock) { IoStatusBlock->Status = STATUS_NO_MORE_FILES_; IoStatusBlock->Information = 0; }
		return STATUS_NO_MORE_FILES_;
	}

	const std::string &fname = en.names[en.pos];
	std::filesystem::path full = fobj->canonicalPath / fname;
	struct stat stbuf{};
	bool haveStat = ::stat(full.c_str(), &stbuf) == 0;
	bool isDir = haveStat && S_ISDIR(stbuf.st_mode);

	size_t nameOff = fileNameOffsetForClass(FileInformationClass);
	size_t nameBytes = fname.size() * sizeof(uint16_t);
	size_t need = nameOff + nameBytes;
	if (Length < need) {
		if (IoStatusBlock) { IoStatusBlock->Status = STATUS_BUFFER_OVERFLOW_; IoStatusBlock->Information = 0; }
		return STATUS_BUFFER_OVERFLOW_;
	}

	uint8_t *b = static_cast<uint8_t *>(FileInformation);
	std::memset(b, 0, nameOff);
	uint64_t ft = unixToFiletime(haveStat ? stbuf.st_mtime : 0);
	uint32_t attrs = isDir ? 0x10u : 0x20u; // DIRECTORY : ARCHIVE
	uint64_t size = (haveStat && !isDir) ? static_cast<uint64_t>(stbuf.st_size) : 0;

	if (FileInformationClass == 12) { // FileNamesInformation
		putU32(b, 0, 0);                       // NextEntryOffset
		putU32(b, 4, 0);                       // FileIndex
		putU32(b, 8, static_cast<uint32_t>(nameBytes));
	} else {
		putU32(b, 0, 0);                       // NextEntryOffset (single/last)
		putU32(b, 4, 0);                       // FileIndex
		putU64(b, 8, ft);                      // CreationTime
		putU64(b, 16, ft);                     // LastAccessTime
		putU64(b, 24, ft);                     // LastWriteTime
		putU64(b, 32, ft);                     // ChangeTime
		putU64(b, 40, size);                   // EndOfFile
		putU64(b, 48, size);                   // AllocationSize
		putU32(b, 56, attrs);                  // FileAttributes
		putU32(b, 60, static_cast<uint32_t>(nameBytes)); // FileNameLength
		// EaSize / ShortName / FileId already zeroed by memset for classes != 1.
	}
	// Write the file name as UTF-16 at the class-specific offset.
	uint16_t *namePtr = reinterpret_cast<uint16_t *>(b + nameOff);
	for (size_t i = 0; i < fname.size(); ++i) {
		namePtr[i] = static_cast<uint16_t>(static_cast<unsigned char>(fname[i]));
	}

	en.pos++;
	if (IoStatusBlock) { IoStatusBlock->Status = STATUS_SUCCESS_; IoStatusBlock->Information = need; }
	return STATUS_SUCCESS_;
}

} // namespace ntdll
