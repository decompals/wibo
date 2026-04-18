#include "winbase.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "files.h"
#include "heap.h"
#include "internal.h"
#include "mimalloc/types.h"
#include "modules.h"
#include "resources.h"
#include "strutil.h"
#include "types.h"

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <limits>
#include <mimalloc.h>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <sys/statvfs.h>
#if defined(__APPLE__)
#include <mach/mach.h>
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <sys/sysinfo.h>
#endif
#include <system_error>
#include <unordered_map>
#include <vector>

namespace {

constexpr UINT GMEM_MOVEABLE = 0x0002;
constexpr UINT GMEM_ZEROINIT = 0x0040;
constexpr UINT GMEM_MODIFY = 0x0080;

constexpr UINT LMEM_MOVEABLE = 0x0002;
constexpr UINT LMEM_ZEROINIT = 0x0040;

constexpr ATOM kMinIntegerAtom = 0x0001;
constexpr ATOM kMaxIntegerAtom = 0xBFFF;
constexpr ATOM kMinStringAtom = 0xC000;
constexpr ATOM kMaxStringAtom = 0xFFFF;

SIZE_T clampToSizeT(uint64_t value) {
	constexpr uint64_t kMaxSizeT = static_cast<uint64_t>(std::numeric_limits<SIZE_T>::max());
	return value > kMaxSizeT ? static_cast<SIZE_T>(kMaxSizeT) : static_cast<SIZE_T>(value);
}

struct MemorySnapshot {
	uint64_t totalPhys = 0;
	uint64_t availPhys = 0;
	uint64_t totalPageFile = 0;
	uint64_t availPageFile = 0;
};

bool queryHostMemory(MemorySnapshot &out) {
#if defined(__linux__)
	struct sysinfo info {};
	if (sysinfo(&info) != 0) {
		return false;
	}
	const uint64_t unit = info.mem_unit ? static_cast<uint64_t>(info.mem_unit) : 1;
	out.totalPhys = static_cast<uint64_t>(info.totalram) * unit;
	out.availPhys = static_cast<uint64_t>(info.freeram) * unit;
	out.totalPageFile = (static_cast<uint64_t>(info.totalram) + static_cast<uint64_t>(info.totalswap)) * unit;
	out.availPageFile = (static_cast<uint64_t>(info.freeram) + static_cast<uint64_t>(info.freeswap)) * unit;
	if (info.bufferram > 0) {
		uint64_t buffers = static_cast<uint64_t>(info.bufferram) * unit;
		out.availPhys += buffers;
		out.availPageFile += buffers;
	}
	return true;
#elif defined(__APPLE__)
	uint64_t totalPhys = 0;
	size_t totalPhysSize = sizeof(totalPhys);
	if (sysctlbyname("hw.memsize", &totalPhys, &totalPhysSize, nullptr, 0) != 0) {
		return false;
	}
	vm_size_t pageSize = 0;
	if (host_page_size(mach_host_self(), &pageSize) != KERN_SUCCESS || pageSize == 0) {
		return false;
	}
	vm_statistics64_data_t vmstat {};
	mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
	if (host_statistics64(mach_host_self(), HOST_VM_INFO64, reinterpret_cast<host_info64_t>(&vmstat), &count) !=
		KERN_SUCCESS) {
		return false;
	}
	uint64_t freePages = static_cast<uint64_t>(vmstat.free_count) + static_cast<uint64_t>(vmstat.inactive_count) +
						 static_cast<uint64_t>(vmstat.speculative_count);
	out.totalPhys = totalPhys;
	out.availPhys = freePages * static_cast<uint64_t>(pageSize);

	struct xsw_usage swap {};
	size_t swapSize = sizeof(swap);
	if (sysctlbyname("vm.swapusage", &swap, &swapSize, nullptr, 0) == 0 && swapSize == sizeof(swap)) {
		out.totalPageFile = swap.xsu_total;
		out.availPageFile = swap.xsu_avail;
	} else {
		out.totalPageFile = totalPhys;
		out.availPageFile = out.availPhys;
	}
	return true;
#else
	return false;
#endif
}

struct AtomData {
	uint16_t refCount = 0;
	std::string original;
};

struct AtomTable {
	std::mutex mutex;
	std::unordered_map<std::string, ATOM> stringToAtom;
	std::unordered_map<ATOM, AtomData> atomToData;
	ATOM nextStringAtom = kMinStringAtom;
};

AtomTable &localAtomTable() {
	static AtomTable table;
	return table;
}

ATOM allocateStringAtomLocked(AtomTable &table) {
	constexpr unsigned int kRange = static_cast<unsigned int>(kMaxStringAtom - kMinStringAtom + 1);
	unsigned int startOffset = 0;
	if (table.nextStringAtom >= kMinStringAtom && table.nextStringAtom <= kMaxStringAtom) {
		startOffset = static_cast<unsigned int>(table.nextStringAtom - kMinStringAtom);
	}
	for (unsigned int i = 0; i < kRange; ++i) {
		unsigned int offset = (startOffset + i) % kRange;
		ATOM candidate = static_cast<ATOM>(kMinStringAtom + offset);
		if (table.atomToData.find(candidate) == table.atomToData.end()) {
			table.nextStringAtom = static_cast<ATOM>(candidate + 1);
			if (table.nextStringAtom > kMaxStringAtom) {
				table.nextStringAtom = kMinStringAtom;
			}
			return candidate;
		}
	}
	return 0;
}

bool tryHandleIntegerAtomPointer(const void *ptr, ATOM &atomOut) {
	uintptr_t value = reinterpret_cast<uintptr_t>(ptr);
	if ((value >> 16) != 0) {
		return false;
	}
	ATOM maybeAtom = static_cast<ATOM>(value & 0xFFFFu);
	if (maybeAtom < kMinIntegerAtom || maybeAtom > kMaxIntegerAtom) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		atomOut = 0;
		return true;
	}
	atomOut = maybeAtom;
	return true;
}

ATOM findAtomByNormalizedKey(const std::string &normalizedKey) {
	auto &table = localAtomTable();
	std::lock_guard lk(table.mutex);
	auto it = table.stringToAtom.find(normalizedKey);
	if (it == table.stringToAtom.end()) {
		kernel32::setLastError(ERROR_FILE_NOT_FOUND);
		return 0;
	}
	return it->second;
}

ATOM tryParseIntegerAtomString(const std::string &value, bool &handled) {
	handled = false;
	if (value.empty() || value[0] != '#') {
		return 0;
	}
	char *end = nullptr;
	unsigned long parsed = std::strtoul(value.c_str() + 1, &end, 10);
	if (end == value.c_str() + 1 || *end != '\0') {
		return 0;
	}
	handled = true;
	if (parsed < kMinIntegerAtom || parsed > kMaxIntegerAtom) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	return static_cast<ATOM>(parsed);
}

ATOM findAtomByString(const std::string &value) {
	bool handledInteger = false;
	ATOM atom = tryParseIntegerAtomString(value, handledInteger);
	if (handledInteger) {
		return atom;
	}
	std::string normalized = stringToLower(value);
	return findAtomByNormalizedKey(normalized);
}

ATOM addAtomByString(const std::string &value) {
	bool handledInteger = false;
	ATOM atom = tryParseIntegerAtomString(value, handledInteger);
	if (handledInteger) {
		return atom;
	}
	if (value.empty() || value.size() > 255) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	std::string normalized = stringToLower(value);
	auto &table = localAtomTable();
	std::lock_guard lk(table.mutex);
	auto existing = table.stringToAtom.find(normalized);
	if (existing != table.stringToAtom.end()) {
		auto dataIt = table.atomToData.find(existing->second);
		if (dataIt != table.atomToData.end() && dataIt->second.refCount < std::numeric_limits<uint16_t>::max()) {
			dataIt->second.refCount++;
		}
		return existing->second;
	}
	ATOM newAtom = allocateStringAtomLocked(table);
	if (newAtom == 0) {
		kernel32::setLastError(ERROR_NOT_ENOUGH_MEMORY);
		return 0;
	}
	AtomData data;
	data.refCount = 1;
	data.original = value;
	table.stringToAtom.emplace(std::move(normalized), newAtom);
	table.atomToData.emplace(newAtom, std::move(data));
	return newAtom;
}

bool tryGetCurrentDirectoryPath(std::string &outPath) {
	std::error_code ec;
	std::filesystem::path cwd = std::filesystem::current_path(ec);
	if (ec) {
		kernel32::setLastError(wibo::winErrorFromErrno(ec.value()));
		return false;
	}
	outPath = files::pathToWindows(cwd);
	return true;
}

bool computeLongWindowsPath(const std::string &inputPath, std::string &longPath) {
	bool hasTrailingSlash = false;
	if (!inputPath.empty()) {
		char last = inputPath.back();
		hasTrailingSlash = (last == '\\' || last == '/');
	}

	auto hostPath = files::pathFromWindows(inputPath.c_str());
	if (hostPath.empty()) {
		kernel32::setLastError(ERROR_PATH_NOT_FOUND);
		return false;
	}

	std::error_code ec;
	if (!std::filesystem::exists(hostPath, ec)) {
		kernel32::setLastError(ERROR_FILE_NOT_FOUND);
		return false;
	}

	longPath = files::pathToWindows(hostPath);
	if (hasTrailingSlash && !longPath.empty() && longPath.back() != '\\') {
		longPath.push_back('\\');
	}
	return true;
}

bool resolveDiskFreeSpaceStat(const char *rootPathName, struct statvfs &outBuf, std::string &resolvedPath) {
	std::filesystem::path hostPath;
	if (rootPathName && *rootPathName) {
		hostPath = files::pathFromWindows(rootPathName);
	} else {
		std::error_code ec;
		hostPath = std::filesystem::current_path(ec);
		if (ec) {
			kernel32::setLastError(ERROR_PATH_NOT_FOUND);
			return false;
		}
	}
	if (hostPath.empty()) {
		kernel32::setLastError(ERROR_PATH_NOT_FOUND);
		return false;
	}

	hostPath = hostPath.lexically_normal();
	if (hostPath.empty()) {
		hostPath = std::filesystem::path("/");
	}

	std::error_code ec;
	if (!hostPath.is_absolute()) {
		auto abs = std::filesystem::absolute(hostPath, ec);
		if (ec) {
			kernel32::setLastError(ERROR_PATH_NOT_FOUND);
			return false;
		}
		hostPath = abs;
	}

	std::filesystem::path queryPath = hostPath;
	while (true) {
		std::string query = queryPath.empty() ? std::string("/") : queryPath.string();
		if (query.empty()) {
			query = "/";
		}
		if (statvfs(query.c_str(), &outBuf) == 0) {
			resolvedPath = query;
			return true;
		}

		int savedErrno = errno;
		if (savedErrno != ENOENT && savedErrno != ENOTDIR) {
			kernel32::setLastError(wibo::winErrorFromErrno(savedErrno));
			return false;
		}

		std::filesystem::path parent = queryPath.parent_path();
		if (parent == queryPath) {
			kernel32::setLastError(wibo::winErrorFromErrno(savedErrno));
			return false;
		}
		if (parent.empty()) {
			parent = std::filesystem::path("/");
		}
		queryPath = parent;
	}
}

constexpr DWORD kComputerNameLength = 8;
constexpr DWORD kComputerNameRequiredSize = kComputerNameLength + 1;
constexpr const char kComputerNameAnsi[] = "COMPNAME";
const uint16_t kComputerNameWide[] = {u'C', u'O', u'M', u'P', u'N', u'A', u'M', u'E', 0};

struct DllRedirectionEntry {
	std::string nameLower;
	wibo::heap::guest_ptr<ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION> dllData;
};

struct ActivationContext {
	std::vector<DllRedirectionEntry> dllRedirections;
};

wibo::heap::guest_ptr<ActivationContext> g_builtinActCtx;

ActivationContext *currentActivationContext() {
	if (!g_builtinActCtx) {
		g_builtinActCtx = wibo::heap::make_guest_unique<ActivationContext>();
	}
	return g_builtinActCtx.get();
}

} // namespace

void ensureDefaultActivationContext() {
	static std::once_flag initFlag;
	std::call_once(initFlag, [] {
		ActivationContext *ctx = currentActivationContext();
		auto addDll = [ctx](const std::string &name) {
			DllRedirectionEntry entry;
			entry.nameLower = stringToLower(name);
			entry.dllData = wibo::heap::make_guest_unique<ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION>();
			entry.dllData->Size = sizeof(entry.dllData);
			entry.dllData->Flags = ACTIVATION_CONTEXT_DATA_DLL_REDIRECTION_PATH_OMITS_ASSEMBLY_ROOT;
			entry.dllData->TotalPathLength = 0;
			entry.dllData->PathSegmentCount = 0;
			entry.dllData->PathSegmentOffset = 0;
			ctx->dllRedirections.emplace_back(std::move(entry));
		};
		for (const auto &[key, module] : wibo::allLoadedModules()) {
			if (!module->moduleStub) {
				addDll(module->normalizedName);
			}
		}
	});
}

namespace kernel32 {

ATOM WINAPI AddAtomA(LPCSTR lpString) {
	HOST_CONTEXT_GUARD();
	ATOM atom = 0;
	if (tryHandleIntegerAtomPointer(lpString, atom)) {
		DEBUG_LOG("AddAtomA(int:%u)\n", atom);
		return atom;
	}
	DEBUG_LOG("AddAtomA(%s)\n", lpString ? lpString : "<null>");
	if (!lpString) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	size_t len = strnlen(lpString, 256);
	if (len == 0 || len >= 256) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	std::string value(lpString, len);
	ATOM result = addAtomByString(value);
	DEBUG_LOG("AddAtomA -> %u (lastError=%u)\n", result, getLastError());
	return result;
}

ATOM WINAPI AddAtomW(LPCWSTR lpString) {
	HOST_CONTEXT_GUARD();
	ATOM atom = 0;
	if (tryHandleIntegerAtomPointer(lpString, atom)) {
		DEBUG_LOG("AddAtomW(int:%u)\n", atom);
		return atom;
	}
	if (!lpString) {
		DEBUG_LOG("AddAtomW(<null>)\n");
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	size_t len = wstrnlen(reinterpret_cast<const uint16_t *>(lpString), 256);
	if (len == 0 || len >= 256) {
		DEBUG_LOG("AddAtomW(invalid length)\n");
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	std::string value = wideStringToString(reinterpret_cast<const uint16_t *>(lpString), static_cast<int>(len));
	DEBUG_LOG("AddAtomW(%s)\n", value.c_str());
	ATOM result = addAtomByString(value);
	DEBUG_LOG("AddAtomW -> %u (lastError=%u)\n", result, getLastError());
	return result;
}

ATOM WINAPI FindAtomA(LPCSTR lpString) {
	HOST_CONTEXT_GUARD();
	ATOM atom = 0;
	if (tryHandleIntegerAtomPointer(lpString, atom)) {
		DEBUG_LOG("FindAtomA(int:%u)\n", atom);
		return atom;
	}
	DEBUG_LOG("FindAtomA(%s)\n", lpString ? lpString : "<null>");
	if (!lpString) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	size_t len = strnlen(lpString, 256);
	if (len == 0 || len >= 256) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	std::string value(lpString, len);
	ATOM result = findAtomByString(value);
	DEBUG_LOG("FindAtomA -> %u (lastError=%u)\n", result, getLastError());
	return result;
}

ATOM WINAPI FindAtomW(LPCWSTR lpString) {
	HOST_CONTEXT_GUARD();
	ATOM atom = 0;
	if (tryHandleIntegerAtomPointer(lpString, atom)) {
		DEBUG_LOG("FindAtomW(int:%u)\n", atom);
		return atom;
	}
	if (!lpString) {
		DEBUG_LOG("FindAtomW(<null>)\n");
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	size_t len = wstrnlen(reinterpret_cast<const uint16_t *>(lpString), 256);
	if (len == 0 || len >= 256) {
		DEBUG_LOG("FindAtomW(invalid length)\n");
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	std::string value = wideStringToString(reinterpret_cast<const uint16_t *>(lpString), static_cast<int>(len));
	DEBUG_LOG("FindAtomW(%s)\n", value.c_str());
	ATOM result = findAtomByString(value);
	DEBUG_LOG("FindAtomW -> %u (lastError=%u)\n", result, getLastError());
	return result;
}

UINT WINAPI GetAtomNameA(ATOM nAtom, LPSTR lpBuffer, int nSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetAtomNameA(%u, %p, %d)\n", nAtom, lpBuffer, nSize);
	if (!lpBuffer || nSize <= 0) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	std::string value;
	if (nAtom >= kMinIntegerAtom && nAtom <= kMaxIntegerAtom) {
		value = '#';
		value += std::to_string(nAtom);
	} else {
		auto &table = localAtomTable();
		std::lock_guard lk(table.mutex);
		auto it = table.atomToData.find(nAtom);
		if (it == table.atomToData.end()) {
			kernel32::setLastError(ERROR_INVALID_HANDLE);
			return 0;
		}
		value = it->second.original;
	}
	if (value.size() + 1 > static_cast<size_t>(nSize)) {
		kernel32::setLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}
	std::memcpy(lpBuffer, value.c_str(), value.size());
	lpBuffer[value.size()] = '\0';
	UINT written = static_cast<UINT>(value.size());
	DEBUG_LOG("GetAtomNameA -> %u (lastError=%u)\n", written, getLastError());
	return written;
}

UINT WINAPI GetAtomNameW(ATOM nAtom, LPWSTR lpBuffer, int nSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetAtomNameW(%u, %p, %d)\n", nAtom, lpBuffer, nSize);
	if (!lpBuffer || nSize <= 0) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	std::string narrow;
	if (nAtom >= kMinIntegerAtom && nAtom <= kMaxIntegerAtom) {
		narrow = '#';
		narrow += std::to_string(nAtom);
	} else {
		auto &table = localAtomTable();
		std::lock_guard lk(table.mutex);
		auto it = table.atomToData.find(nAtom);
		if (it == table.atomToData.end()) {
			kernel32::setLastError(ERROR_INVALID_HANDLE);
			return 0;
		}
		narrow = it->second.original;
	}
	auto wide = stringToWideString(narrow.c_str(), narrow.size());
	size_t needed = wide.size();
	if (needed > static_cast<size_t>(nSize)) {
		kernel32::setLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}
	std::memcpy(lpBuffer, wide.data(), needed * sizeof(uint16_t));
	if (needed > 0) {
		lpBuffer[needed - 1] = 0;
	}
	UINT written = static_cast<UINT>(needed ? needed - 1 : 0);
	DEBUG_LOG("GetAtomNameW -> %u (lastError=%u)\n", written, getLastError());
	return written;
}

UINT WINAPI SetHandleCount(UINT uNumber) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetHandleCount(%u)\n", uNumber);
	(void)uNumber;
	return 0x3FFE;
}

// MESSAGETABLE resource layout (RT_MESSAGETABLE = 11). Produced by MC.EXE,
// embedded into the PE by RC.EXE. See WinNT.h / MSDN "Message Resources".
constexpr WORD kRtMessageTable = 11;
constexpr WORD kMessageResourceUnicode = 0x0001;

struct MessageResourceBlock {
	DWORD LowId;
	DWORD HighId;
	DWORD OffsetToEntries;
};
struct MessageResourceData {
	DWORD NumberOfBlocks;
	MessageResourceBlock Blocks[1];  // Blocks[NumberOfBlocks]
};
struct MessageResourceEntry {
	WORD Length;   // total size incl. this header
	WORD Flags;    // bit 0 set => UTF-16 text
	BYTE Text[1];  // Length-4 bytes, null-terminated
};

// Locate and copy out the message string for dwMessageId in hModule's
// RT_MESSAGETABLE resource. Writes the resulting narrow-ANSI template
// into outTemplate. Returns false if the id isn't present.
static bool loadMessageTemplateFromModule(HMODULE hModule, DWORD dwMessageId, std::string &outTemplate) {
	auto *exe = wibo::executableFromModule(hModule);
	DEBUG_LOG("  MESSAGETABLE lookup: hMod=%p exe=%p id=%u\n", hModule, exe, dwMessageId);
	if (!exe) return false;
	auto typeId = wibo::ResourceIdentifier::fromID(kRtMessageTable);
	auto nameId = wibo::ResourceIdentifier::fromID(1);
	wibo::ResourceLocation loc;
	if (!exe->findResource(typeId, nameId, std::nullopt, loc)) {
		DEBUG_LOG("  MESSAGETABLE lookup: findResource failed for type=%u name=1\n", kRtMessageTable);
		return false;
	}
	DEBUG_LOG("  MESSAGETABLE lookup: resource size=%zu at %p\n", loc.size, loc.data);
	if (loc.size < sizeof(MessageResourceData)) return false;
	const auto *data = reinterpret_cast<const MessageResourceData *>(loc.data);
	DEBUG_LOG("  MESSAGETABLE lookup: NumberOfBlocks=%u\n", data->NumberOfBlocks);
	const auto *blocks = data->Blocks;
	for (DWORD bi = 0; bi < data->NumberOfBlocks; bi++) {
		const auto &blk = blocks[bi];
		DEBUG_LOG("    block %u: LowId=%u HighId=%u Offset=0x%x\n", bi, blk.LowId, blk.HighId, blk.OffsetToEntries);
		if (dwMessageId < blk.LowId || dwMessageId > blk.HighId) continue;
		auto index = dwMessageId - blk.LowId;
		const auto *entry =
			reinterpret_cast<const MessageResourceEntry *>(static_cast<const uint8_t *>(loc.data) + blk.OffsetToEntries);
		for (DWORD ei = 0; ei < index; ei++) {
			entry = reinterpret_cast<const MessageResourceEntry *>(
				reinterpret_cast<const uint8_t *>(entry) + entry->Length);
		}
		const size_t textBytes = entry->Length > offsetof(MessageResourceEntry, Text)
									 ? entry->Length - offsetof(MessageResourceEntry, Text)
									 : 0;
		if (entry->Flags & kMessageResourceUnicode) {
			int wideLen = static_cast<int>(textBytes / sizeof(uint16_t));
			outTemplate = wideStringToString(reinterpret_cast<const uint16_t *>(entry->Text), wideLen);
		} else {
			outTemplate.assign(reinterpret_cast<const char *>(entry->Text), textBytes);
		}
		// MC emits trailing \r\n\0 (or \0). Trim any trailing NULs.
		while (!outTemplate.empty() && outTemplate.back() == '\0') outTemplate.pop_back();
		DEBUG_LOG("  MESSAGETABLE lookup: found template len=%zu\n", outTemplate.size());
		return true;
	}
	return false;
}

// Substitute %1..%99 in a message template with the caller-supplied
// arguments. If ignoreInserts is true, inserts pass through verbatim.
// Arguments come from a va_list when FORMAT_MESSAGE_ARGUMENT_ARRAY is
// not set, or from a DWORD_PTR array otherwise. For the stubbed arg
// model here we accept a simple pointer-to-pointer array which covers
// RC / LINK / NMAKE usage.
static std::string applyMessageInserts(const std::string &tpl, const uint32_t *args, DWORD argCount,
									   bool ignoreInserts) {
	std::string out;
	out.reserve(tpl.size());
	for (size_t i = 0; i < tpl.size(); ) {
		char c = tpl[i];
		if (c != '%' || ignoreInserts) {
			out.push_back(c);
			i++;
			continue;
		}
		i++;
		if (i >= tpl.size()) { out.push_back('%'); break; }
		if (!std::isdigit(static_cast<unsigned char>(tpl[i]))) {
			char esc = tpl[i++];
			switch (esc) {
			case '0': return out;
			case 'n': out.push_back('\n'); break;
			case 'r': out.push_back('\r'); break;
			case 'b': out.push_back(' '); break;
			case '.': out.push_back('.'); break;
			case '!': out.push_back('!'); break;
			case 't': out.push_back('\t'); break;
			case '%':
			default:  out.push_back('%'); out.push_back(esc); break;
			}
			continue;
		}
		unsigned int n = 0;
		while (i < tpl.size() && std::isdigit(static_cast<unsigned char>(tpl[i])) && n < 100) {
			n = n * 10 + (tpl[i++] - '0');
		}
		// Parse a trailing "!<format>!" section (MC format spec).
		std::string fmtSpec;
		if (i < tpl.size() && tpl[i] == '!') {
			i++;
			size_t fmtStart = i;
			while (i < tpl.size() && tpl[i] != '!') i++;
			fmtSpec = tpl.substr(fmtStart, i - fmtStart);
			if (i < tpl.size()) i++;
		}
		if (n >= 1 && n <= argCount && args) {
			auto arg = static_cast<uintptr_t>(args[n - 1]);
			if (fmtSpec == "ws" || fmtSpec == "ls") {
				const auto *ws = reinterpret_cast<const uint16_t *>(arg);
				if (ws && arg > 0x10000) {
					while (*ws) {
						out.push_back(static_cast<char>(*ws > 0x7f ? '?' : *ws));
						ws++;
					}
				}
			} else {
				char tmp[32];
				const char *s = reinterpret_cast<const char *>(arg);
				if (arg > 0x10000 && s) {
					out.append(s);
				} else {
					int written = std::snprintf(tmp, sizeof(tmp), "%u", static_cast<unsigned>(args[n - 1]));
					if (written > 0) out.append(tmp, written);
				}
			}
		} else {
			char tmp[8];
			int written = std::snprintf(tmp, sizeof(tmp), "%%%u", n);
			if (written > 0) out.append(tmp, written);
		}
	}
	return out;
}

DWORD WINAPI FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer,
							DWORD nSize, LPVOID Arguments) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("FormatMessageA(0x%x, %p, %u, %u, %p, %u, %p)\n", dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer,
			  nSize, Arguments);
	(void)dwLanguageId;

	constexpr DWORD kAllocateBuffer  = 0x00000100;
	constexpr DWORD kIgnoreInserts   = 0x00000200;
	constexpr DWORD kFromString      = 0x00000400;
	constexpr DWORD kFromHModule     = 0x00000800;
	constexpr DWORD kFromSystem      = 0x00001000;
	constexpr DWORD kArgumentArray   = 0x00002000;

	// Step 1: locate the message template.
	std::string tpl;
	bool haveTpl = false;
	if (dwFlags & kFromString) {
		if (lpSource) {
			tpl.assign(static_cast<const char *>(lpSource));
			haveTpl = true;
		}
	} else if (dwFlags & kFromHModule) {
		// HMODULE is a small integer in wibo; lpSource carries it via a
		// cast from HMODULE -> void* at the caller. Round-trip via uintptr.
		HMODULE hMod = static_cast<HMODULE>(reinterpret_cast<uintptr_t>(lpSource));
		haveTpl = loadMessageTemplateFromModule(hMod, dwMessageId, tpl);
	} else if (dwFlags & kFromSystem) {
		tpl = std::system_category().message(static_cast<int>(dwMessageId));
		haveTpl = true;
	}

	if (!haveTpl) {
		setLastError(ERROR_RESOURCE_LANG_NOT_FOUND);
		return 0;
	}

	// Step 2: apply inserts if not suppressed.
	std::string formatted;
	if (dwFlags & kIgnoreInserts) {
		formatted = std::move(tpl);
	} else {
		// The guest is 32-bit: arguments are 4-byte values.
		// FORMAT_MESSAGE_ARGUMENT_ARRAY: Arguments is a uint32_t[] directly.
		// Otherwise: Arguments is a va_list* (pointer to a char* on i386).
		// Dereference once to get the actual argument array pointer.
		const uint32_t *args = nullptr;
		DWORD argCount = 99;
		if (dwFlags & kArgumentArray) {
			args = reinterpret_cast<const uint32_t *>(Arguments);
		} else if (Arguments) {
			uint32_t vaListPtr = *reinterpret_cast<const uint32_t *>(Arguments);
			args = reinterpret_cast<const uint32_t *>(static_cast<uintptr_t>(vaListPtr));
		}
		formatted = applyMessageInserts(tpl, args, argCount, false);
	}

	// Step 3: write out.
	const size_t len = formatted.size();
	if (dwFlags & kAllocateBuffer) {
		// lpBuffer is really LPSTR* — store an allocated pointer there.
		auto **outPtr = reinterpret_cast<char **>(lpBuffer);
		if (!outPtr) {
			setLastError(ERROR_INVALID_PARAMETER);
			return 0;
		}
		size_t allocSize = std::max(static_cast<size_t>(nSize), len + 1);
		auto *buf = reinterpret_cast<char *>(std::malloc(allocSize));
		if (!buf) {
			setLastError(ERROR_NOT_ENOUGH_MEMORY);
			return 0;
		}
		std::memcpy(buf, formatted.data(), len);
		buf[len] = '\0';
		*outPtr = buf;
		return static_cast<DWORD>(len);
	}

	if (!lpBuffer || nSize == 0) {
		setLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}
	if (len >= nSize) {
		std::memcpy(lpBuffer, formatted.data(), nSize - 1);
		lpBuffer[nSize - 1] = '\0';
		setLastError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}
	std::memcpy(lpBuffer, formatted.data(), len);
	lpBuffer[len] = '\0';
	return static_cast<DWORD>(len);
}

PVOID WINAPI EncodePointer(PVOID Ptr) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("EncodePointer(%p)\n", Ptr);
	return Ptr;
}

PVOID WINAPI DecodePointer(PVOID Ptr) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("DecodePointer(%p)\n", Ptr);
	return Ptr;
}

BOOL WINAPI SetDllDirectoryA(LPCSTR lpPathName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetDllDirectoryA(%s)\n", lpPathName);
	if (!lpPathName || lpPathName[0] == '\0') {
		wibo::clearDllDirectoryOverride();
		return TRUE;
	}

	std::filesystem::path hostPath = files::pathFromWindows(lpPathName);
	if (hostPath.empty() || !std::filesystem::exists(hostPath)) {
		setLastError(ERROR_PATH_NOT_FOUND);
		return FALSE;
	}

	wibo::setDllDirectoryOverride(std::filesystem::absolute(hostPath));
	return TRUE;
}

BOOL WINAPI FindActCtxSectionStringA(DWORD dwFlags, const GUID *lpExtensionGuid, ULONG ulSectionId,
									 LPCSTR lpStringToFind, PACTCTX_SECTION_KEYED_DATA ReturnedData) {
	DEBUG_LOG("FindActCtxSectionStringA(%#x, %p, %u, %s, %p)\n", dwFlags, lpExtensionGuid, ulSectionId,
			  lpStringToFind ? lpStringToFind : "<null>", ReturnedData);
	std::vector<uint16_t> wideStorage;
	if (lpStringToFind) {
		size_t length = strlen(lpStringToFind);
		wideStorage.resize(length + 1);
		for (size_t i = 0; i <= length; ++i) {
			wideStorage[i] = static_cast<uint8_t>(lpStringToFind[i]);
		}
	}
	const uint16_t *widePtr = wideStorage.empty() ? nullptr : wideStorage.data();
	return FindActCtxSectionStringW(dwFlags, lpExtensionGuid, ulSectionId, reinterpret_cast<LPCWSTR>(widePtr),
									ReturnedData);
}

BOOL WINAPI FindActCtxSectionStringW(DWORD dwFlags, const GUID *lpExtensionGuid, ULONG ulSectionId,
									 LPCWSTR lpStringToFind, PACTCTX_SECTION_KEYED_DATA ReturnedData) {
	std::string lookup = lpStringToFind ? wideStringToString(lpStringToFind) : std::string();
	DEBUG_LOG("FindActCtxSectionStringW(%#x, %p, %u, %s, %p)\n", dwFlags, lpExtensionGuid, ulSectionId, lookup.c_str(),
			  ReturnedData);

	if (lpExtensionGuid) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if (!ReturnedData) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if (dwFlags & ~FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	ULONG originalSize = ReturnedData->cbSize;
	if (originalSize < sizeof(ACTCTX_SECTION_KEYED_DATA)) {
		setLastError(ERROR_INSUFFICIENT_BUFFER);
		return FALSE;
	}

	ensureDefaultActivationContext();
	ActivationContext *ctx = currentActivationContext();
	const DllRedirectionEntry *matchedEntry = nullptr;
	if (ulSectionId == ACTIVATION_CONTEXT_SECTION_DLL_REDIRECTION && !lookup.empty()) {
		std::string lowerLookup = stringToLower(lookup);
		for (const auto &entry : ctx->dllRedirections) {
			if (entry.nameLower == lowerLookup) {
				matchedEntry = &entry;
				break;
			}
		}
	}

	size_t zeroSize = std::min(static_cast<size_t>(ReturnedData->cbSize), sizeof(*ReturnedData));
	std::memset(ReturnedData, 0, zeroSize);
	ReturnedData->cbSize = originalSize;
	ReturnedData->ulDataFormatVersion = 1;
	ReturnedData->ulFlags = ACTCTX_SECTION_KEYED_DATA_FLAG_FOUND_IN_ACTCTX;
	if (dwFlags & FIND_ACTCTX_SECTION_KEY_RETURN_HACTCTX) {
		ReturnedData->hActCtx = static_cast<HANDLE>(toGuestPtr(currentActivationContext()));
	}

	if (!matchedEntry) {
		setLastError(ERROR_SXS_KEY_NOT_FOUND);
		return FALSE;
	}

	ReturnedData->lpData = toGuestPtr(matchedEntry->dllData.get());
	ReturnedData->ulLength = matchedEntry->dllData->Size;
	ReturnedData->lpSectionBase = toGuestPtr(matchedEntry->dllData.get());
	ReturnedData->ulSectionTotalLength = matchedEntry->dllData->Size;
	ReturnedData->ulAssemblyRosterIndex = 1;
	ReturnedData->AssemblyMetadata = {};

	return TRUE;
}

void tryMarkExecutable(void *mem) {
	if (!mem) {
		return;
	}
	size_t usable = mi_usable_size(mem);
	if (usable == 0) {
		return;
	}
	long pageSize = sysconf(_SC_PAGESIZE);
	if (pageSize <= 0) {
		return;
	}
	uintptr_t start = reinterpret_cast<uintptr_t>(mem);
	uintptr_t alignedStart = start & ~static_cast<uintptr_t>(pageSize - 1);
	uintptr_t end = (start + usable + pageSize - 1) & ~static_cast<uintptr_t>(pageSize - 1);
	size_t length = static_cast<size_t>(end - alignedStart);
	if (length == 0) {
		return;
	}
	mprotect(reinterpret_cast<void *>(alignedStart), length, PROT_READ | PROT_WRITE | PROT_EXEC);
}

BOOL WINAPI IsBadReadPtr(LPCVOID lp, UINT_PTR ucb) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: IsBadReadPtr(ptr=%p, size=%zu)\n", lp, static_cast<size_t>(ucb));
	if (!lp) {
		return TRUE;
	}
	return FALSE;
}

BOOL WINAPI IsBadWritePtr(LPVOID lp, UINT_PTR ucb) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: IsBadWritePtr(ptr=%p, size=%zu)\n", lp, static_cast<size_t>(ucb));
	if (!lp && ucb != 0) {
		return TRUE;
	}
	return FALSE;
}

BOOL WINAPI GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetComputerNameA(%p, %p)\n", lpBuffer, nSize);
	if (!nSize || !lpBuffer) {
		if (nSize) {
			*nSize = 0;
		}
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if (*nSize < kComputerNameRequiredSize) {
		*nSize = kComputerNameRequiredSize;
		setLastError(ERROR_BUFFER_OVERFLOW);
		return FALSE;
	}

	std::strcpy(lpBuffer, kComputerNameAnsi);
	*nSize = kComputerNameLength;
	return TRUE;
}

BOOL WINAPI GetComputerNameW(LPWSTR lpBuffer, LPDWORD nSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetComputerNameW(%p, %p)\n", lpBuffer, nSize);
	if (!nSize || !lpBuffer) {
		if (nSize) {
			*nSize = 0;
		}
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if (*nSize < kComputerNameRequiredSize) {
		*nSize = kComputerNameRequiredSize;
		setLastError(ERROR_BUFFER_OVERFLOW);
		return FALSE;
	}

	wstrncpy(lpBuffer, kComputerNameWide, static_cast<size_t>(kComputerNameRequiredSize));
	*nSize = kComputerNameLength;
	return TRUE;
}

HGLOBAL WINAPI GlobalAlloc(UINT uFlags, SIZE_T dwBytes) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("GlobalAlloc(%x, %zu)\n", uFlags, static_cast<size_t>(dwBytes));
	if (uFlags & GMEM_MOVEABLE) {
		// not implemented rn
		assert(0);
		return NO_HANDLE;
	}
	bool zero = (uFlags & GMEM_ZEROINIT) != 0;
	void *ret = wibo::heap::guestMalloc(static_cast<UINT>(dwBytes), zero);
	VERBOSE_LOG("-> %p\n", ret);
	if (!ret) {
		setLastError(ERROR_NOT_ENOUGH_MEMORY);
		return GUEST_NULL;
	}
	return toGuestPtr(ret);
}

HGLOBAL WINAPI GlobalFree(HGLOBAL hMem) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("GlobalFree(%p)\n", hMem);
	if (wibo::heap::guestFree(reinterpret_cast<void *>(hMem))) {
		VERBOSE_LOG("-> success\n");
		return GUEST_NULL;
	} else {
		VERBOSE_LOG("-> failure\n");
		return hMem;
	}
}

HGLOBAL WINAPI GlobalReAlloc(HGLOBAL hMem, SIZE_T dwBytes, UINT uFlags) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("GlobalReAlloc(%p, %zu, %x)\n", hMem, static_cast<size_t>(dwBytes), uFlags);
	if (uFlags & GMEM_MODIFY) {
		assert(0);
		return GUEST_NULL;
	}
	bool zero = (uFlags & GMEM_ZEROINIT) != 0;
	void *ret = wibo::heap::guestRealloc(reinterpret_cast<void *>(hMem), static_cast<UINT>(dwBytes), zero);
	VERBOSE_LOG("-> %p\n", ret);
	if (!ret) {
		setLastError(ERROR_NOT_ENOUGH_MEMORY);
		return GUEST_NULL;
	}
	return toGuestPtr(ret);
}

UINT WINAPI GlobalFlags(HGLOBAL hMem) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("GlobalFlags(%p)\n", hMem);
	(void)hMem;
	return 0;
}

void WINAPI GlobalMemoryStatus(LPMEMORYSTATUS lpBuffer) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GlobalMemoryStatus(%p)\n", lpBuffer);
	if (!lpBuffer) {
		return;
	}

	std::memset(lpBuffer, 0, sizeof(*lpBuffer));
	lpBuffer->dwLength = sizeof(*lpBuffer);

	MemorySnapshot snapshot;
	if (!queryHostMemory(snapshot)) {
		return;
	}

	uint64_t totalPhys = snapshot.totalPhys;
	uint64_t availPhys = snapshot.availPhys;
	uint64_t totalPageFile = snapshot.totalPageFile;
	uint64_t availPageFile = snapshot.availPageFile;

	constexpr uint64_t kMinAppAddr = 0x00010000ULL;
	constexpr uint64_t kMaxAppAddr = 0x7FFEFFFFULL;
	uint64_t totalVirtual = kMaxAppAddr - kMinAppAddr + 1;
	uint64_t availVirtual = totalVirtual;

	constexpr uint64_t kMaxLegacy = static_cast<uint64_t>(std::numeric_limits<LONG>::max());
	totalPhys = std::min(totalPhys, kMaxLegacy);
	availPhys = std::min(availPhys, kMaxLegacy);
	totalVirtual = std::min(totalVirtual, kMaxLegacy);
	availVirtual = std::min(availVirtual, kMaxLegacy);
	availPhys = std::min(availPhys, totalPhys);
	availPageFile = std::min(availPageFile, totalPageFile);
	availVirtual = std::min(availVirtual, totalVirtual);

	if (totalPhys > 0) {
		uint64_t used = totalPhys > availPhys ? totalPhys - availPhys : 0;
		uint64_t load = (used * 100) / totalPhys;
		lpBuffer->dwMemoryLoad = static_cast<DWORD>(std::min<uint64_t>(load, 100));
	}

	lpBuffer->dwTotalPhys = clampToSizeT(totalPhys);
	lpBuffer->dwAvailPhys = clampToSizeT(availPhys);
	lpBuffer->dwTotalPageFile = clampToSizeT(totalPageFile);
	lpBuffer->dwAvailPageFile = clampToSizeT(availPageFile);
	lpBuffer->dwTotalVirtual = clampToSizeT(totalVirtual);
	lpBuffer->dwAvailVirtual = clampToSizeT(availVirtual);
}

HLOCAL WINAPI LocalAlloc(UINT uFlags, SIZE_T uBytes) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("LocalAlloc(%x, %zu)\n", uFlags, static_cast<size_t>(uBytes));
	bool zero = (uFlags & LMEM_ZEROINIT) != 0;
	if ((uFlags & LMEM_MOVEABLE) != 0) {
		VERBOSE_LOG("  ignoring LMEM_MOVEABLE\n");
	}
	void *result = wibo::heap::guestMalloc(static_cast<UINT>(uBytes), zero);
	if (!result) {
		setLastError(ERROR_NOT_ENOUGH_MEMORY);
		return GUEST_NULL;
	}
	// Legacy Windows applications (pre-NX and DEP) may expect executable memory from LocalAlloc.
	tryMarkExecutable(result);
	VERBOSE_LOG("  -> %p\n", result);
	return toGuestPtr(result);
}

HLOCAL WINAPI LocalFree(HLOCAL hMem) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("LocalFree(%p)\n", hMem);
	if (wibo::heap::guestFree(reinterpret_cast<void *>(hMem))) {
		VERBOSE_LOG("-> success\n");
		return GUEST_NULL;
	} else {
		VERBOSE_LOG("-> failure\n");
		setLastError(ERROR_INVALID_HANDLE);
		return hMem;
	}
}

HLOCAL WINAPI LocalReAlloc(HLOCAL hMem, SIZE_T uBytes, UINT uFlags) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("LocalReAlloc(%p, %zu, %x)\n", hMem, static_cast<size_t>(uBytes), uFlags);
	bool zero = (uFlags & LMEM_ZEROINIT) != 0;
	if ((uFlags & LMEM_MOVEABLE) != 0) {
		VERBOSE_LOG("  ignoring LMEM_MOVEABLE\n");
	}
	void *result = wibo::heap::guestRealloc(reinterpret_cast<void *>(hMem), static_cast<UINT>(uBytes), zero);
	if (!result && uBytes != 0) {
		setLastError(ERROR_NOT_ENOUGH_MEMORY);
		return GUEST_NULL;
	}
	// Legacy Windows applications (pre-NX and DEP) may expect executable memory from LocalReAlloc.
	tryMarkExecutable(result);
	VERBOSE_LOG("  -> %p\n", result);
	return toGuestPtr(result);
}

HLOCAL WINAPI LocalHandle(LPCVOID pMem) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("LocalHandle(%p)\n", pMem);
	return toGuestPtr(pMem);
}

LPVOID WINAPI LocalLock(HLOCAL hMem) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("STUB: LocalLock(%p)\n", hMem);
	return reinterpret_cast<void *>(hMem);
}

BOOL WINAPI LocalUnlock(HLOCAL hMem) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("LocalUnlock(%p)\n", hMem);
	(void)hMem;
	return TRUE;
}

SIZE_T WINAPI LocalSize(HLOCAL hMem) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("LocalSize(%p)\n", hMem);
	return hMem ? mi_usable_size(reinterpret_cast<void *>(hMem)) : 0;
}

UINT WINAPI LocalFlags(HLOCAL hMem) {
	HOST_CONTEXT_GUARD();
	VERBOSE_LOG("STUB: LocalFlags(%p)\n", hMem);
	(void)hMem;
	return 0;
}

static constexpr const char *kSystemDirectoryA = "C:\\Windows\\System32";

UINT WINAPI GetSystemDirectoryA(LPSTR lpBuffer, UINT uSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetSystemDirectoryA(%p, %u)\n", lpBuffer, uSize);
	if (!lpBuffer) {
		return 0;
	}

	const auto len = std::strlen(kSystemDirectoryA);
	if (uSize < len + 1) {
		return static_cast<UINT>(len + 1);
	}
	std::strcpy(lpBuffer, kSystemDirectoryA);
	return static_cast<UINT>(len);
}

UINT WINAPI GetSystemDirectoryW(LPWSTR lpBuffer, UINT uSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetSystemDirectoryW(%p, %u)\n", lpBuffer, uSize);
	if (!lpBuffer) {
		return 0;
	}

	auto wide = stringToWideString(kSystemDirectoryA);
	UINT length = static_cast<UINT>(wide.size() - 1);
	if (uSize < length + 1) {
		return length + 1;
	}
	std::memcpy(lpBuffer, wide.data(), (length + 1) * sizeof(uint16_t));
	return length;
}

UINT WINAPI GetSystemWow64DirectoryA(LPSTR lpBuffer, UINT uSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetSystemWow64DirectoryA(%p, %u)\n", lpBuffer, uSize);
	(void)lpBuffer;
	(void)uSize;
	setLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return 0;
}

UINT WINAPI GetSystemWow64DirectoryW(LPWSTR lpBuffer, UINT uSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetSystemWow64DirectoryW(%p, %u)\n", lpBuffer, uSize);
	(void)lpBuffer;
	(void)uSize;
	setLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return 0;
}

UINT WINAPI GetWindowsDirectoryA(LPSTR lpBuffer, UINT uSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetWindowsDirectoryA(%p, %u)\n", lpBuffer, uSize);
	if (!lpBuffer) {
		return 0;
	}

	const char *windowsDir = "C:\\Windows";
	const auto len = std::strlen(windowsDir);
	if (uSize < len + 1) {
		return static_cast<UINT>(len + 1);
	}
	std::strcpy(lpBuffer, windowsDir);
	return static_cast<UINT>(len);
}

UINT WINAPI GetSystemWindowsDirectoryA(LPSTR lpBuffer, UINT uSize) {
	DEBUG_LOG("GetSystemWindowsDirectoryA(%p, %u)\n", lpBuffer, uSize);
	return GetWindowsDirectoryA(lpBuffer, uSize);
}

UINT WINAPI GetSystemWindowsDirectoryW(LPWSTR lpBuffer, UINT uSize) {
	DEBUG_LOG("GetSystemWindowsDirectoryW(%p, %u)\n", lpBuffer, uSize);
	if (!lpBuffer) {
		return 0;
	}

	const char *windowsDir = "C:\\Windows";
	auto wide = stringToWideString(windowsDir);
	UINT length = static_cast<UINT>(wide.size() - 1);
	if (uSize < length + 1) {
		return length + 1;
	}
	std::memcpy(lpBuffer, wide.data(), (length + 1) * sizeof(uint16_t));
	return length;
}

DWORD WINAPI GetCurrentDirectoryA(DWORD nBufferLength, LPSTR lpBuffer) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetCurrentDirectoryA(%u, %p)\n", nBufferLength, lpBuffer);

	std::string path;
	if (!tryGetCurrentDirectoryPath(path)) {
		return 0;
	}

	const DWORD required = static_cast<DWORD>(path.size() + 1);
	if (nBufferLength == 0) {
		return required;
	}
	if (!lpBuffer) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	if (nBufferLength < required) {
		setLastError(ERROR_INSUFFICIENT_BUFFER);
		return required;
	}
	std::memcpy(lpBuffer, path.c_str(), required);
	return required - 1;
}

DWORD WINAPI GetCurrentDirectoryW(DWORD nBufferLength, LPWSTR lpBuffer) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetCurrentDirectoryW(%u, %p)\n", nBufferLength, lpBuffer);

	std::string path;
	if (!tryGetCurrentDirectoryPath(path)) {
		return 0;
	}
	auto widePath = stringToWideString(path.c_str());
	const DWORD required = static_cast<DWORD>(widePath.size());
	if (nBufferLength == 0) {
		return required;
	}
	if (!lpBuffer) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	if (nBufferLength < required) {
		setLastError(ERROR_INSUFFICIENT_BUFFER);
		return required;
	}
	std::copy(widePath.begin(), widePath.end(), lpBuffer);
	return required - 1;
}

int WINAPI SetCurrentDirectoryA(LPCSTR lpPathName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetCurrentDirectoryA(%s)\n", lpPathName ? lpPathName : "(null)");
	if (!lpPathName) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	auto hostPath = files::pathFromWindows(lpPathName);
	std::error_code ec;
	std::filesystem::current_path(hostPath, ec);
	if (ec) {
		setLastError(wibo::winErrorFromErrno(ec.value()));
		return 0;
	}
	return 1;
}

int WINAPI SetCurrentDirectoryW(LPCWSTR lpPathName) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetCurrentDirectoryW\n");
	if (!lpPathName) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	std::string path = wideStringToString(lpPathName);
	return SetCurrentDirectoryA(path.c_str());
}

DWORD WINAPI GetLongPathNameA(LPCSTR lpszShortPath, LPSTR lpszLongPath, DWORD cchBuffer) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetLongPathNameA(%s, %p, %u)\n", lpszShortPath ? lpszShortPath : "(null)", lpszLongPath, cchBuffer);
	if (!lpszShortPath) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	std::string input(lpszShortPath);
	std::string longPath;
	if (!computeLongWindowsPath(input, longPath)) {
		return 0;
	}

	DWORD required = static_cast<DWORD>(longPath.size() + 1);
	if (cchBuffer == 0) {
		return required;
	}
	if (!lpszLongPath) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	if (cchBuffer < required) {
		setLastError(ERROR_INSUFFICIENT_BUFFER);
		return required;
	}
	std::memcpy(lpszLongPath, longPath.c_str(), required);
	return required - 1;
}

DWORD WINAPI GetLongPathNameW(LPCWSTR lpszShortPath, LPWSTR lpszLongPath, DWORD cchBuffer) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetLongPathNameW(%p, %p, %u)\n", lpszShortPath, lpszLongPath, cchBuffer);
	if (!lpszShortPath) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	std::string input = wideStringToString(lpszShortPath);
	std::string longPath;
	if (!computeLongWindowsPath(input, longPath)) {
		return 0;
	}
	auto wideLong = stringToWideString(longPath.c_str());
	DWORD required = static_cast<DWORD>(wideLong.size());
	if (cchBuffer == 0) {
		return required;
	}
	if (!lpszLongPath) {
		setLastError(ERROR_INVALID_PARAMETER);
		return 0;
	}
	if (cchBuffer < required) {
		setLastError(ERROR_INSUFFICIENT_BUFFER);
		return required;
	}
	std::copy(wideLong.begin(), wideLong.end(), lpszLongPath);
	return required - 1;
}

BOOL WINAPI GetDiskFreeSpaceA(LPCSTR lpRootPathName, LPDWORD lpSectorsPerCluster, LPDWORD lpBytesPerSector,
							  LPDWORD lpNumberOfFreeClusters, LPDWORD lpTotalNumberOfClusters) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetDiskFreeSpaceA(%s)\n", lpRootPathName ? lpRootPathName : "(null)");
	struct statvfs buf{};
	std::string resolvedPath;
	if (!resolveDiskFreeSpaceStat(lpRootPathName, buf, resolvedPath)) {
		return FALSE;
	}

	uint64_t blockSize = buf.f_frsize ? buf.f_frsize : buf.f_bsize;
	if (blockSize == 0) {
		blockSize = 4096;
	}
	unsigned int bytesPerSector = 512;
	if (blockSize % bytesPerSector != 0) {
		bytesPerSector =
			static_cast<unsigned int>(std::min<uint64_t>(blockSize, std::numeric_limits<unsigned int>::max()));
	}
	unsigned int sectorsPerCluster = static_cast<unsigned int>(blockSize / bytesPerSector);
	if (sectorsPerCluster == 0) {
		sectorsPerCluster = 1;
		bytesPerSector =
			static_cast<unsigned int>(std::min<uint64_t>(blockSize, std::numeric_limits<unsigned int>::max()));
	}

	uint64_t totalClusters64 = buf.f_blocks;
	uint64_t freeClusters64 = buf.f_bavail;

	if (lpSectorsPerCluster) {
		*lpSectorsPerCluster = sectorsPerCluster;
	}
	if (lpBytesPerSector) {
		*lpBytesPerSector = bytesPerSector;
	}
	if (lpNumberOfFreeClusters) {
		uint64_t clamped = std::min<uint64_t>(freeClusters64, std::numeric_limits<unsigned int>::max());
		*lpNumberOfFreeClusters = static_cast<DWORD>(clamped);
	}
	if (lpTotalNumberOfClusters) {
		uint64_t clamped = std::min<uint64_t>(totalClusters64, std::numeric_limits<unsigned int>::max());
		*lpTotalNumberOfClusters = static_cast<DWORD>(clamped);
	}

	DEBUG_LOG("\t-> host %s, spc %u, bps %u, free clusters %u, total clusters %u\n", resolvedPath.c_str(),
			  lpSectorsPerCluster ? *lpSectorsPerCluster : 0, lpBytesPerSector ? *lpBytesPerSector : 0,
			  lpNumberOfFreeClusters ? *lpNumberOfFreeClusters : 0,
			  lpTotalNumberOfClusters ? *lpTotalNumberOfClusters : 0);
	return TRUE;
}

BOOL WINAPI GetDiskFreeSpaceW(LPCWSTR lpRootPathName, LPDWORD lpSectorsPerCluster, LPDWORD lpBytesPerSector,
							  LPDWORD lpNumberOfFreeClusters, LPDWORD lpTotalNumberOfClusters) {
	HOST_CONTEXT_GUARD();
	std::string rootPath = wideStringToString(lpRootPathName);
	return GetDiskFreeSpaceA(lpRootPathName ? rootPath.c_str() : nullptr, lpSectorsPerCluster, lpBytesPerSector,
							 lpNumberOfFreeClusters, lpTotalNumberOfClusters);
}

BOOL WINAPI GetDiskFreeSpaceExA(LPCSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller,
								PULARGE_INTEGER lpTotalNumberOfBytes, PULARGE_INTEGER lpTotalNumberOfFreeBytes) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetDiskFreeSpaceExA(%s)\n", lpDirectoryName ? lpDirectoryName : "(null)");
	struct statvfs buf{};
	std::string resolvedPath;
	if (!resolveDiskFreeSpaceStat(lpDirectoryName, buf, resolvedPath)) {
		return FALSE;
	}

	uint64_t blockSize = buf.f_frsize ? buf.f_frsize : buf.f_bsize;
	if (blockSize == 0) {
		blockSize = 4096;
	}

	uint64_t freeToCaller = static_cast<uint64_t>(buf.f_bavail) * blockSize;
	uint64_t totalBytes = static_cast<uint64_t>(buf.f_blocks) * blockSize;
	uint64_t totalFree = static_cast<uint64_t>(buf.f_bfree) * blockSize;

	if (lpFreeBytesAvailableToCaller) {
		lpFreeBytesAvailableToCaller->QuadPart = freeToCaller;
	}
	if (lpTotalNumberOfBytes) {
		lpTotalNumberOfBytes->QuadPart = totalBytes;
	}
	if (lpTotalNumberOfFreeBytes) {
		lpTotalNumberOfFreeBytes->QuadPart = totalFree;
	}

	DEBUG_LOG("\t-> host %s, free %llu, total %llu, total free %llu\n", resolvedPath.c_str(),
			  static_cast<unsigned long long>(freeToCaller), static_cast<unsigned long long>(totalBytes),
			  static_cast<unsigned long long>(totalFree));
	return TRUE;
}

BOOL WINAPI GetDiskFreeSpaceExW(LPCWSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller,
								PULARGE_INTEGER lpTotalNumberOfBytes, PULARGE_INTEGER lpTotalNumberOfFreeBytes) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetDiskFreeSpaceExW -> ");
	std::string directoryName = wideStringToString(lpDirectoryName);
	return GetDiskFreeSpaceExA(lpDirectoryName ? directoryName.c_str() : nullptr, lpFreeBytesAvailableToCaller,
							   lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes);
}

} // namespace kernel32
