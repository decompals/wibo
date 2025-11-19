#include "processes.h"

#include "common.h"
#include "files.h"
#include "handles.h"
#include "kernel32/internal.h"

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include <pthread.h>

#ifdef __APPLE__
extern char **environ;
#endif

using kernel32::ProcessObject;

namespace wibo {

ProcessManager::ProcessManager() : mImpl(detail::createProcessManagerImpl()) {}

ProcessManager::~ProcessManager() = default;

bool ProcessManager::init() {
	if (!mImpl) {
		return false;
	}
	return mImpl->init();
}

void ProcessManager::shutdown() {
	if (mImpl) {
		mImpl->shutdown();
	}
}

bool ProcessManager::addProcess(Pin<ProcessObject> po) {
	if (!mImpl) {
		return false;
	}
	return mImpl->addProcess(std::move(po));
}

bool ProcessManager::running() const { return mImpl && mImpl->running(); }

ProcessManager &processes() {
	static ProcessManager mgr;
	if (!mgr.init()) {
		std::fprintf(stderr, "Failed to initialize ProcessManager\n");
		std::abort();
	}
	return mgr;
}

static bool hasDirectoryComponent(const std::string &command) {
	return command.find('/') != std::string::npos || command.find('\\') != std::string::npos ||
		   command.find(':') != std::string::npos;
}

static bool hasExtension(const std::string &command) {
	auto pos = command.find_last_of('.');
	auto slash = command.find_last_of("/\\");
	return pos != std::string::npos && (slash == std::string::npos || pos > slash + 1);
}

static std::vector<std::string> pathextValues() {
	const char *envValue = std::getenv("PATHEXT");
	std::string raw = envValue ? envValue : ".COM;.EXE;.BAT;.CMD";
	std::vector<std::string> exts;
	size_t start = 0;
	while (start <= raw.size()) {
		size_t end = raw.find(';', start);
		if (end == std::string::npos) {
			end = raw.size();
		}
		std::string part = raw.substr(start, end - start);
		if (!part.empty()) {
			if (part[0] != '.') {
				part.insert(part.begin(), '.');
			}
			exts.push_back(part);
		}
		if (end == raw.size()) {
			break;
		}
		start = end + 1;
	}
	if (exts.empty()) {
		exts = {".COM", ".EXE", ".BAT", ".CMD"};
	}
	return exts;
}

static std::vector<std::filesystem::path> parseHostPath(const std::string &value) {
	std::vector<std::filesystem::path> paths;
	const char *delims = std::strchr(value.c_str(), ';') ? ";" : ":";
	size_t start = 0;
	while (start <= value.size()) {
		size_t end = value.find_first_of(delims, start);
		if (end == std::string::npos) {
			end = value.size();
		}
		std::string entry = value.substr(start, end - start);
		if (!entry.empty()) {
			bool looksWindows =
				entry.find('\\') != std::string::npos || (entry.size() >= 2 && entry[1] == ':' && entry[0] != '/');
			std::filesystem::path candidate;
			if (looksWindows) {
				auto converted = files::pathFromWindows(entry.c_str());
				if (!converted.empty()) {
					candidate = converted;
				}
			}
			if (candidate.empty()) {
				candidate = std::filesystem::path(entry);
			}
			paths.push_back(std::move(candidate));
		}
		if (end == value.size()) {
			break;
		}
		start = end + 1;
	}
	return paths;
}

static std::vector<std::filesystem::path> buildSearchDirectories() {
	std::vector<std::filesystem::path> dirs;
	if (wibo::guestExecutablePath.has_parent_path()) {
		dirs.push_back(wibo::guestExecutablePath.parent_path());
	}
	dirs.push_back(std::filesystem::current_path());
	const auto addFromEnv = [&](const char *envVar) {
		if (const char *envPath = std::getenv(envVar)) {
			auto parsed = parseHostPath(envPath);
			dirs.insert(dirs.end(), parsed.begin(), parsed.end());
		}
	};
	addFromEnv("WIBO_PATH");
	addFromEnv("WINEPATH");
	addFromEnv("PATH");
	return dirs;
}

std::optional<std::filesystem::path> resolveExecutable(const std::string &command, bool searchPath) {
	if (command.empty()) {
		return std::nullopt;
	}

	std::vector<std::string> candidates;
	candidates.push_back(command);
	if (!hasExtension(command)) {
		for (const auto &ext : pathextValues()) {
			candidates.push_back(command + ext);
		}
	}

	auto tryResolveDirect = [&](const std::string &name) -> std::optional<std::filesystem::path> {
		auto host = files::pathFromWindows(name.c_str());
		if (host.empty()) {
			std::string normalized = name;
			std::replace(normalized.begin(), normalized.end(), '\\', '/');
			host = std::filesystem::path(normalized);
		}
		std::filesystem::path parent =
			host.parent_path().empty() ? std::filesystem::current_path() : host.parent_path();
		std::string filename = host.filename().string();
		auto resolved = files::findCaseInsensitiveFile(parent, filename);
		if (resolved) {
			return files::canonicalPath(*resolved);
		}
		std::error_code ec;
		if (!filename.empty() && std::filesystem::exists(host, ec)) {
			return files::canonicalPath(host);
		}
		return std::nullopt;
	};

	if (hasDirectoryComponent(command)) {
		for (const auto &name : candidates) {
			auto resolved = tryResolveDirect(name);
			if (resolved) {
				return resolved;
			}
		}
		return std::nullopt;
	}

	if (searchPath) {
		auto dirs = buildSearchDirectories();
		for (const auto &dir : dirs) {
			for (const auto &name : candidates) {
				auto resolved = files::findCaseInsensitiveFile(dir, name);
				if (resolved) {
					return files::canonicalPath(*resolved);
				}
			}
		}
	}

	return std::nullopt;
}

static int spawnInternal(const std::vector<std::string> &args, Pin<kernel32::ProcessObject> &pinOut) {
	std::vector<char *> argv;
	argv.reserve(args.size() + 2);
	argv.push_back(const_cast<char *>("wibo"));
	for (auto &arg : args) {
		argv.push_back(const_cast<char *>(arg.c_str()));
	}
	argv.push_back(nullptr);

	if (wibo::debugEnabled) {
		std::string cmdline;
		for (size_t i = 1; i < argv.size() - 1; ++i) {
			if (i != 1) {
				cmdline += ' ';
			}
			cmdline += '\'';
			cmdline += argv[i];
			cmdline += '\'';
		}
		DEBUG_LOG("Spawning process: %s %s\n", argv[0], cmdline.c_str());
	}

	std::vector<std::string> ownedEnv;
	ownedEnv.reserve(256);
	for (char **e = environ; *e; ++e) {
		if (std::strncmp(*e, "WIBO_DEBUG_INDENT=", 18) != 0)
			ownedEnv.emplace_back(*e);
	}
	ownedEnv.emplace_back("WIBO_DEBUG_INDENT=" + std::to_string(wibo::debugIndent + 1));

	std::vector<char *> envp;
	envp.reserve(ownedEnv.size() + 1);
	for (auto &s : ownedEnv)
		envp.push_back(const_cast<char *>(s.c_str()));
	envp.push_back(nullptr);

	detail::SpawnProcessInfo info;
	int rc = detail::spawnProcess(argv.data(), envp.data(), info);
	if (rc != 0) {
		return rc;
	}

	DEBUG_LOG("Spawned process with PID %d (pidfd=%d)\n", info.pid, info.pidfd);

	auto obj = make_pin<kernel32::ProcessObject>(info.pid, info.pidfd, true);
	pinOut = obj.clone();
	if (!processes().addProcess(std::move(obj))) {
		std::fprintf(stderr, "Failed to add process to process manager\n");
		std::abort();
	}
	return 0;
}

int spawnWithCommandLine(const std::string &applicationName, const std::string &commandLine,
						 Pin<kernel32::ProcessObject> &pinOut) {
	if (applicationName.empty() && commandLine.empty()) {
		return ENOENT;
	}

	std::vector<std::string> args;
	args.reserve(3);
	if (!commandLine.empty()) {
		args.emplace_back("--cmdline");
		args.push_back(commandLine);
	}
	if (!applicationName.empty()) {
		args.push_back(applicationName);
	}

	return spawnInternal(args, pinOut);
}

int spawnWithArgv(const std::string &applicationName, const std::vector<std::string> &argv,
				  Pin<kernel32::ProcessObject> &pinOut) {
	if (applicationName.empty() && argv.empty()) {
		return ENOENT;
	}

	std::vector<std::string> args;
	args.reserve(argv.size() + 1);
	if (!applicationName.empty()) {
		args.push_back(applicationName);
	}
	args.emplace_back("--");
	for (const auto &arg : argv) {
		args.push_back(arg);
	}

	return spawnInternal(args, pinOut);
}

std::vector<std::string> splitCommandLine(const char *commandLine) {
	std::vector<std::string> result;
	if (!commandLine) {
		return result;
	}
	std::string input(commandLine);
	size_t i = 0;
	size_t len = input.size();
	while (i < len) {
		while (i < len && (input[i] == ' ' || input[i] == '\t')) {
			++i;
		}
		if (i >= len) {
			break;
		}
		std::string arg;
		bool inQuotes = false;
		int backslashes = 0;
		for (; i < len; ++i) {
			char c = input[i];
			if (c == '\\') {
				++backslashes;
				continue;
			}
			if (c == '"') {
				if ((backslashes % 2) == 0) {
					arg.append(backslashes / 2, '\\');
					inQuotes = !inQuotes;
				} else {
					arg.append(backslashes / 2, '\\');
					arg.push_back('"');
				}
				backslashes = 0;
				continue;
			}
			arg.append(backslashes, '\\');
			backslashes = 0;
			if (!inQuotes && (c == ' ' || c == '\t')) {
				break;
			}
			arg.push_back(c);
		}
		arg.append(backslashes, '\\');
		result.push_back(std::move(arg));
		while (i < len && (input[i] == ' ' || input[i] == '\t')) {
			++i;
		}
	}
	return result;
}

DWORD getThreadId() {
#if defined(HAVE_PTHREAD_GETTID_NP)
	pid_t threadId = pthread_gettid_np(pthread_self());
#elif defined(__linux__)
	pid_t threadId = gettid();
#elif defined(__APPLE__)
	uint64_t threadId = 0;
	pthread_threadid_np(nullptr, &threadId);
#else
#error "Unknown platform"
#endif
	return static_cast<DWORD>(threadId);
}

} // namespace wibo
