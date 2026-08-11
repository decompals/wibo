#include "files.h"
#include "common.h"
#include "errors.h"
#include "handles.h"
#include "strutil.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <system_error>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <utility>

kernel32::FsObject::~FsObject() {
	int fd = std::exchange(this->fd, -1);
	if (fd >= 0 && closeOnDestroy) {
		close(fd);
	}
	if (deletePending && !canonicalPath.empty()) {
		if (unlink(canonicalPath.c_str()) == 0) {
			files::invalidatePathCache(canonicalPath.parent_path());
		} else {
			perror("Failed to delete file on close");
		}
	}
}

namespace files {

namespace {

struct DirectoryIdentity {
	dev_t device = 0;
	ino_t inode = 0;
	mode_t mode = 0;
	off_t size = 0;
	time_t modifiedSeconds = 0;
	long modifiedNanoseconds = 0;
	time_t changedSeconds = 0;
	long changedNanoseconds = 0;

	bool operator==(const DirectoryIdentity &) const = default;
};

struct DirectoryCacheEntry {
	DirectoryIdentity identity;
	std::unordered_map<std::string, std::string> names;
	std::unordered_set<std::string> exactNames;
	std::unordered_set<std::string> negativeNames;
};

struct DirectoryAlias {
	DirectoryIdentity identity;
	std::string canonicalKey;
};

struct NegativePathCacheEntry {
	std::filesystem::path resolvedPath;
	std::filesystem::path checkedDirectory;
	DirectoryIdentity directoryIdentity;
	std::string canonicalDirectoryKey;
	int error = 0;
};

struct CachedNameResult {
	std::optional<std::string> realName;
	std::optional<DirectoryIdentity> directoryIdentity;
	std::string canonicalDirectoryKey;
	bool cacheUsable = false;
};

std::shared_mutex g_pathCacheMutex;
std::unordered_map<std::string, DirectoryCacheEntry> g_directoryCache;
std::unordered_map<std::string, DirectoryAlias> g_directoryAliases;
std::unordered_map<std::string, NegativePathCacheEntry> g_negativePathCache;

DirectoryIdentity identityFromStat(const struct stat &st) {
	DirectoryIdentity identity;
	identity.device = st.st_dev;
	identity.inode = st.st_ino;
	identity.mode = st.st_mode;
	identity.size = st.st_size;
#if defined(__APPLE__)
	identity.modifiedSeconds = st.st_mtimespec.tv_sec;
	identity.modifiedNanoseconds = st.st_mtimespec.tv_nsec;
	identity.changedSeconds = st.st_ctimespec.tv_sec;
	identity.changedNanoseconds = st.st_ctimespec.tv_nsec;
#elif defined(__linux__)
	identity.modifiedSeconds = st.st_mtim.tv_sec;
	identity.modifiedNanoseconds = st.st_mtim.tv_nsec;
	identity.changedSeconds = st.st_ctim.tv_sec;
	identity.changedNanoseconds = st.st_ctim.tv_nsec;
#else
	identity.modifiedSeconds = st.st_mtime;
	identity.changedSeconds = st.st_ctime;
#endif
	return identity;
}

std::string lexicalAbsoluteKey(const std::filesystem::path &path) {
	std::error_code ec;
	const std::filesystem::path &effectivePath = path.empty() ? std::filesystem::path(".") : path;
	auto absolute = std::filesystem::absolute(effectivePath, ec);
	if (ec) {
		return effectivePath.lexically_normal().string();
	}
	return absolute.lexically_normal().string();
}

std::string lowercaseName(const std::string &name) {
	std::string result = name;
	toLowerInPlace(result);
	return result;
}

void eraseNegativeEntriesForDirectoryLocked(const std::string &canonicalKey) {
	for (auto it = g_negativePathCache.begin(); it != g_negativePathCache.end();) {
		if (it->second.canonicalDirectoryKey == canonicalKey) {
			it = g_negativePathCache.erase(it);
		} else {
			++it;
		}
	}
}

std::optional<std::string> cachedCanonicalDirectoryKey(const std::string &aliasKey, const DirectoryIdentity &identity) {
	std::shared_lock lock(g_pathCacheMutex);
	auto alias = g_directoryAliases.find(aliasKey);
	if (alias != g_directoryAliases.end() && alias->second.identity == identity) {
		return alias->second.canonicalKey;
	}
	return std::nullopt;
}

std::optional<std::string> canonicalDirectoryKey(const std::filesystem::path &directory, const std::string &aliasKey,
												 const DirectoryIdentity &identity) {
	if (auto cached = cachedCanonicalDirectoryKey(aliasKey, identity)) {
		return cached;
	}

	std::error_code ec;
	auto canonical = std::filesystem::canonical(directory, ec);
	if (ec) {
		return std::nullopt;
	}
	std::string key = canonical.lexically_normal().string();
	std::unique_lock lock(g_pathCacheMutex);
	g_directoryAliases[aliasKey] = DirectoryAlias{identity, key};
	return key;
}

std::optional<std::string> selectCachedName(const DirectoryCacheEntry &entry, const std::filesystem::path &directory,
											const std::string &filename, const std::string &lowered) {
	auto found = entry.names.find(lowered);
	if (found == entry.names.end()) {
		return std::nullopt;
	}
	if (!entry.exactNames.contains(filename) || found->second == filename) {
		return found->second;
	}

	// Normally exact membership is enough to preserve the old exact-first
	// behavior without another stat. A case-colliding dangling symlink is the
	// exception: filesystem::exists used to reject it, then readdir order won.
	struct stat exactStat{};
	if (::stat((directory / filename).c_str(), &exactStat) == 0) {
		return filename;
	}
	return found->second;
}

CachedNameResult lookupCachedName(const std::filesystem::path &inputDirectory, const std::string &filename) {
	const std::filesystem::path directory = inputDirectory.empty() ? std::filesystem::path(".") : inputDirectory;
	struct stat directoryStat{};
	if (::stat(directory.c_str(), &directoryStat) != 0 || !S_ISDIR(directoryStat.st_mode)) {
		return {};
	}

	DirectoryIdentity identity = identityFromStat(directoryStat);
	std::string aliasKey = lexicalAbsoluteKey(directory);
	auto key = canonicalDirectoryKey(directory, aliasKey, identity);
	if (!key) {
		return {};
	}
	std::string lowered = lowercaseName(filename);

	{
		std::shared_lock lock(g_pathCacheMutex);
		auto cached = g_directoryCache.find(*key);
		if (cached != g_directoryCache.end() && cached->second.identity == identity) {
			if (auto found = selectCachedName(cached->second, directory, filename, lowered)) {
				return {std::move(found), identity, *key, true};
			}
			if (cached->second.negativeNames.contains(lowered)) {
				return {std::nullopt, identity, *key, true};
			}
		}
	}

	DirectoryCacheEntry rebuilt;
	rebuilt.identity = identity;
	std::error_code ec;
	std::filesystem::directory_iterator end;
	for (std::filesystem::directory_iterator it(directory, ec); !ec && it != end; it.increment(ec)) {
		std::string name = it->path().filename().string();
		rebuilt.exactNames.emplace(name);
		rebuilt.names.emplace(lowercaseName(name), name);
	}
	if (ec) {
		return {};
	}

	std::optional<std::string> result;
	result = selectCachedName(rebuilt, directory, filename, lowered);
	if (!result) {
		rebuilt.negativeNames.emplace(lowered);
	}

	{
		std::unique_lock lock(g_pathCacheMutex);
		auto cached = g_directoryCache.find(*key);
		if (cached == g_directoryCache.end() || !(cached->second.identity == identity)) {
			eraseNegativeEntriesForDirectoryLocked(*key);
			g_directoryCache.insert_or_assign(*key, std::move(rebuilt));
		} else {
			result = selectCachedName(cached->second, directory, filename, lowered);
			if (!result) {
				cached->second.negativeNames.emplace(lowered);
			}
		}
	}
	return {result, identity, *key, true};
}

std::optional<NegativePathCacheEntry> cachedNegativePath(const std::string &pathKey) {
	std::shared_lock lock(g_pathCacheMutex);
	auto cached = g_negativePathCache.find(pathKey);
	if (cached == g_negativePathCache.end()) {
		return std::nullopt;
	}
	return cached->second;
}

void cacheNegativePath(const std::string &pathKey, NegativePathCacheEntry entry) {
	std::unique_lock lock(g_pathCacheMutex);
	g_negativePathCache.insert_or_assign(pathKey, std::move(entry));
}

} // namespace

static std::vector<std::string> splitList(const std::string &value, char delimiter) {
	std::vector<std::string> entries;
	size_t start = 0;
	while (start <= value.size()) {
		size_t end = value.find(delimiter, start);
		if (end == std::string::npos) {
			end = value.size();
		}
		entries.emplace_back(value.substr(start, end - start));
		if (end == value.size()) {
			break;
		}
		start = end + 1;
	}
	return entries;
}

static std::string toWindowsPathEntry(const std::string &entry) {
	if (entry.empty()) {
		return {};
	}
	bool looksWindows =
		entry.find('\\') != std::string::npos || (entry.size() >= 2 && entry[1] == ':' && entry[0] != '/');
	if (looksWindows) {
		std::string normalized = entry;
		std::replace(normalized.begin(), normalized.end(), '/', '\\');
		return normalized;
	}
	return pathToWindows(std::filesystem::path(entry));
}

static std::string toHostPathEntry(const std::string &entry) {
	if (entry.empty()) {
		return {};
	}
	auto converted = pathFromWindows(entry.c_str());
	if (!converted.empty()) {
		return converted.string();
	}
	std::string normalized = entry;
	std::replace(normalized.begin(), normalized.end(), '\\', '/');
	return normalized;
}

static HANDLE stdinHandle;
static HANDLE stdoutHandle;
static HANDLE stderrHandle;

// Strip the Windows trailing-dot "no extension" convention from each path
// component. Windows treats "foo." and "foo" as the same filename — the
// trailing dot means "no extension" — and many NT-era tools rely on that
// equivalence (notably NMAKE's @<< temp response files like "nm12345."
// and older makefile directives like "!INCLUDE .\sources."). Linux
// filesystems rarely carry a literal trailing-dot name, so normalize
// before our lookup / case-insensitive fallback runs.
static std::string stripTrailingDots(const std::string &s) {
	std::string out;
	out.reserve(s.size());
	size_t i = 0;
	while (i < s.size()) {
		size_t start = i;
		while (i < s.size() && s[i] != '/') {
			i++;
		}
		size_t end = i;
		size_t len = end - start;
		// Leave "." and ".." untouched.
		bool isDotDir = (len == 1 && s[start] == '.') || (len == 2 && s[start] == '.' && s[start + 1] == '.');
		if (!isDotDir) {
			while (end > start && s[end - 1] == '.') {
				end--;
			}
		}
		out.append(s, start, end - start);
		if (i < s.size()) {
			out.push_back('/');
			i++;
		}
	}
	return out;
}

PathResolution resolvePathFromWindows(const char *inStr) {
	// Convert to forward slashes
	std::string str = inStr;
	std::replace(str.begin(), str.end(), '\\', '/');

	// Remove "//?/" prefix
	if (str.rfind("//?/", 0) == 0) {
		str.erase(0, 4);
	}

	// Remove the drive letter
	if (str.rfind("z:/", 0) == 0 || str.rfind("Z:/", 0) == 0 || str.rfind("c:/", 0) == 0 || str.rfind("C:/", 0) == 0) {
		str.erase(0, 2);
	}

	// Apply Windows trailing-dot normalization per path component.
	str = stripTrailingDots(str);

	// Return as-is after one stat if it exists, else traverse the directory
	// caches looking for a path that matches case insensitively.
	std::filesystem::path path = std::filesystem::path(str).lexically_normal();
	struct stat pathStat{};
	if (::stat(path.c_str(), &pathStat) == 0) {
		return {path, pathStat, 0};
	}
	int pathError = errno;
	std::string pathKey = path.empty() ? std::string() : lexicalAbsoluteKey(path);
	if (!pathKey.empty()) {
		if (auto negative = cachedNegativePath(pathKey)) {
			struct stat directoryStat{};
			if (::stat(negative->checkedDirectory.c_str(), &directoryStat) == 0 &&
				identityFromStat(directoryStat) == negative->directoryIdentity) {
				return {negative->resolvedPath, std::nullopt, negative->error};
			}
			std::unique_lock lock(g_pathCacheMutex);
			g_negativePathCache.erase(pathKey);
		}
	}

	std::filesystem::path newPath = ".";
	bool followingExisting = true;
	std::optional<NegativePathCacheEntry> negativeEntry;
	for (const auto &component : path) {
		std::filesystem::path newPath2 = newPath / component;
		bool isLexicalComponent = component == ".." || component == "." || component == "" || component == "/";
		if (followingExisting && !isLexicalComponent) {
			CachedNameResult match = lookupCachedName(newPath, component.string());
			if (match.realName) {
				newPath2 = newPath / *match.realName;
			} else if (!match.cacheUsable) {
				// Preserve exact lookup through directories that can be searched but
				// cannot be enumerated or canonicalized (for example execute-only dirs).
				struct stat exactStat{};
				if (::stat(newPath2.c_str(), &exactStat) != 0) {
					followingExisting = false;
				}
			} else {
				followingExisting = false;
				if (!pathKey.empty() && match.directoryIdentity) {
					negativeEntry =
						NegativePathCacheEntry{{}, newPath, *match.directoryIdentity, match.canonicalDirectoryKey, 0};
				}
			}
		}
		newPath = newPath2;
	}
	if (followingExisting) {
		DEBUG_LOG("Resolved case-insensitive path: %s\n", newPath.c_str());
		struct stat resolvedStat{};
		if (::stat(newPath.c_str(), &resolvedStat) == 0) {
			return {newPath, resolvedStat, 0};
		}
		return {newPath, std::nullopt, errno};
	} else {
		DEBUG_LOG("Failed to resolve path: %s\n", newPath.c_str());
	}
	struct stat resolvedStat{};
	if (::stat(newPath.c_str(), &resolvedStat) == 0) {
		return {newPath, resolvedStat, 0};
	}
	int resolvedError = errno;
	if (negativeEntry) {
		negativeEntry->resolvedPath = newPath;
		negativeEntry->error = resolvedError;
		cacheNegativePath(pathKey, std::move(*negativeEntry));
	}

	return {newPath, std::nullopt, resolvedError != 0 ? resolvedError : pathError};
}

std::filesystem::path pathFromWindows(const char *inStr) { return resolvePathFromWindows(inStr).path; }

std::string pathToWindows(const std::filesystem::path &path) {
	std::string str = path.lexically_normal();

	if (path.is_absolute()) {
		str.insert(0, "Z:");
	}

	std::replace(str.begin(), str.end(), '/', '\\');
	return str;
}

void invalidatePathCache(const std::filesystem::path &inputDirectory) {
	const std::filesystem::path directory = inputDirectory.empty() ? std::filesystem::path(".") : inputDirectory;
	std::string aliasKey = lexicalAbsoluteKey(directory);
	struct stat directoryStat{};
	bool haveIdentity = ::stat(directory.c_str(), &directoryStat) == 0;

	std::unique_lock lock(g_pathCacheMutex);
	std::unordered_set<std::string> canonicalKeys;
	if (auto alias = g_directoryAliases.find(aliasKey); alias != g_directoryAliases.end()) {
		canonicalKeys.emplace(alias->second.canonicalKey);
	}
	if (haveIdentity) {
		for (const auto &[unusedAlias, alias] : g_directoryAliases) {
			(void)unusedAlias;
			if (alias.identity.device == directoryStat.st_dev && alias.identity.inode == directoryStat.st_ino) {
				canonicalKeys.emplace(alias.canonicalKey);
			}
		}
	}
	for (const auto &key : canonicalKeys) {
		g_directoryCache.erase(key);
		eraseNegativeEntriesForDirectoryLocked(key);
	}
	for (auto it = g_directoryAliases.begin(); it != g_directoryAliases.end();) {
		if (it->first == aliasKey || canonicalKeys.contains(it->second.canonicalKey)) {
			it = g_directoryAliases.erase(it);
		} else {
			++it;
		}
	}
}

IOResult read(FileObject *file, void *buffer, size_t bytesToRead, const std::optional<off_t> &offset,
			  bool updateFilePointer) {
	IOResult result{};
	if (!file || !file->valid()) {
		result.unixError = EBADF;
		return result;
	}
	if (bytesToRead == 0) {
		return result;
	}

	// Sanity check: if no offset is given, we must update the file pointer
	assert(offset.has_value() || updateFilePointer);

	if (file->isPipe) {
		std::lock_guard lk(file->m);
		size_t chunk = bytesToRead > SSIZE_MAX ? SSIZE_MAX : bytesToRead;
		uint8_t *in = static_cast<uint8_t *>(buffer);
		ssize_t rc;
		while (true) {
			rc = ::read(file->fd, in, chunk);
			if (rc == -1 && errno == EINTR) {
				continue;
			}
			break;
		}
		if (rc == -1) {
			result.unixError = errno ? errno : EIO;
			return result;
		}
		if (rc == 0) {
			result.reachedEnd = true;
			return result;
		}
		result.bytesTransferred = static_cast<size_t>(rc);
		return result;
	}

	const auto doRead = [&](off_t pos) {
		size_t total = 0;
		size_t remaining = bytesToRead;
		uint8_t *in = static_cast<uint8_t *>(buffer);
		while (remaining > 0) {
			size_t chunk = remaining > SSIZE_MAX ? SSIZE_MAX : remaining;
			ssize_t rc = pread(file->fd, in + total, chunk, pos);
			if (rc == -1) {
				if (errno == EINTR) {
					continue;
				}
				result.unixError = errno ? errno : EIO;
				break;
			}
			if (rc == 0) {
				result.reachedEnd = true;
				break;
			}
			total += static_cast<size_t>(rc);
			remaining -= static_cast<size_t>(rc);
			pos += rc;
		}
		result.bytesTransferred = total;
	};

	if (updateFilePointer || !offset.has_value()) {
		std::lock_guard lk(file->m);
		const off_t pos = offset.value_or(file->filePos);
		doRead(pos);
		if (updateFilePointer) {
			file->filePos = pos + static_cast<off_t>(result.bytesTransferred);
		}
	} else {
		doRead(*offset);
	}

	return result;
}

IOResult write(FileObject *file, const void *buffer, size_t bytesToWrite, const std::optional<off_t> &offset,
			   bool updateFilePointer) {
	IOResult result{};
	if (!file || !file->valid()) {
		result.unixError = EBADF;
		return result;
	}
	if (bytesToWrite == 0) {
		return result;
	}

	// Sanity check: if no offset is given, we must update the file pointer
	assert(offset.has_value() || updateFilePointer);

	if (file->appendOnly || file->isPipe) {
		std::lock_guard lk(file->m);
		size_t total = 0;
		size_t remaining = bytesToWrite;
		const uint8_t *in = static_cast<const uint8_t *>(buffer);
		while (remaining > 0) {
			size_t chunk = remaining > SSIZE_MAX ? SSIZE_MAX : remaining;
			ssize_t rc = ::write(file->fd, in + total, chunk);
			if (rc == -1) {
				if (errno == EINTR) {
					continue;
				}
				result.unixError = errno ? errno : EIO;
				break;
			}
			if (rc == 0) {
				break;
			}
			total += static_cast<size_t>(rc);
			remaining -= static_cast<size_t>(rc);
		}
		result.bytesTransferred = total;
		if (updateFilePointer) {
			off_t pos = file->isPipe ? 0 : lseek(file->fd, 0, SEEK_CUR);
			if (pos >= 0) {
				file->filePos = pos;
			} else if (result.unixError == 0) {
				result.unixError = errno ? errno : EIO;
			}
		}
		return result;
	}

	auto doWrite = [&](off_t pos) {
		size_t total = 0;
		size_t remaining = bytesToWrite;
		const uint8_t *in = static_cast<const uint8_t *>(buffer);
		while (remaining > 0) {
			size_t chunk = remaining > SSIZE_MAX ? SSIZE_MAX : remaining;
			ssize_t rc = pwrite(file->fd, in + total, chunk, pos);
			if (rc == -1) {
				if (errno == EINTR) {
					continue;
				}
				result.unixError = errno ? errno : EIO;
				break;
			}
			if (rc == 0) {
				break;
			}
			total += static_cast<size_t>(rc);
			remaining -= static_cast<size_t>(rc);
			pos += rc;
		}
		result.bytesTransferred = total;
	};

	if (updateFilePointer || !offset.has_value()) {
		std::lock_guard lk(file->m);
		const off_t pos = offset.value_or(file->filePos);
		doWrite(pos);
		if (updateFilePointer) {
			file->filePos = pos + static_cast<off_t>(result.bytesTransferred);
		}
	} else {
		doWrite(*offset);
	}

	return result;
}

HANDLE getStdHandle(DWORD nStdHandle) {
	switch (nStdHandle) {
	case STD_INPUT_HANDLE:
		return stdinHandle;
	case STD_OUTPUT_HANDLE:
		return stdoutHandle;
	case STD_ERROR_HANDLE:
		return stderrHandle;
	default:
		return INVALID_HANDLE_VALUE;
	}
}

BOOL setStdHandle(DWORD nStdHandle, HANDLE hHandle) {
	switch (nStdHandle) {
	case STD_INPUT_HANDLE:
		stdinHandle = hHandle;
		break;
	case STD_OUTPUT_HANDLE:
		stdoutHandle = hHandle;
		break;
	case STD_ERROR_HANDLE:
		stderrHandle = hHandle;
		break;
	default:
		return 0; // fail
	}
	return 1; // success
}

void init() {
	signal(SIGPIPE, SIG_IGN);
	auto &handles = wibo::handles();
	auto stdinObject = make_pin<FileObject>(STDIN_FILENO);
	stdinObject->closeOnDestroy = false;
	stdinHandle = handles.alloc(std::move(stdinObject), FILE_GENERIC_READ, 0);
	auto stdoutObject = make_pin<FileObject>(STDOUT_FILENO);
	stdoutObject->closeOnDestroy = false;
	stdoutObject->appendOnly = true;
	stdoutHandle = handles.alloc(std::move(stdoutObject), FILE_GENERIC_WRITE, 0);
	auto stderrObject = make_pin<FileObject>(STDERR_FILENO);
	stderrObject->closeOnDestroy = false;
	stderrObject->appendOnly = true;
	stderrHandle = handles.alloc(std::move(stderrObject), FILE_GENERIC_WRITE, 0);
}

std::optional<std::filesystem::path> findCaseInsensitiveFile(const std::filesystem::path &directory,
															 const std::string &filename) {
	if (directory.empty()) {
		return std::nullopt;
	}
	auto direct = directory / filename;
	struct stat directStat{};
	if (::stat(direct.c_str(), &directStat) == 0) {
		return canonicalPath(direct);
	}
	CachedNameResult match = lookupCachedName(directory, filename);
	if (match.realName) {
		return canonicalPath(directory / *match.realName);
	}
	return std::nullopt;
}

std::filesystem::path canonicalPath(const std::filesystem::path &path) {
	std::error_code ec;
	auto canonical = std::filesystem::weakly_canonical(path, ec);
	if (!ec) {
		return canonical;
	}
	return std::filesystem::absolute(path);
}

std::string hostPathListToWindows(const std::string &value) {
	if (value.empty()) {
		return value;
	}
	char delimiter = value.find(';') != std::string::npos ? ';' : ':';
	auto entries = splitList(value, delimiter);
	std::string result;
	for (size_t i = 0; i < entries.size(); ++i) {
		if (i != 0) {
			result.push_back(';');
		}
		if (!entries[i].empty()) {
			result += toWindowsPathEntry(entries[i]);
		}
	}
	return result;
}

std::string windowsPathListToHost(const std::string &value) {
	if (value.empty()) {
		return value;
	}
	auto entries = splitList(value, ';');
	std::string result;
	for (size_t i = 0; i < entries.size(); ++i) {
		if (i != 0) {
			result.push_back(':');
		}
		if (!entries[i].empty()) {
			result += toHostPathEntry(entries[i]);
		}
	}
	return result;
}
} // namespace files
