#include "processes.h"
#include "common.h"
#include "files.h"
#include "handles.h"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <spawn.h>
#include <strings.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

extern "C" char **environ;

namespace processes {
    void *allocProcessHandle(pid_t pid) {
		auto* process = new Process;
		process->pid = pid;
		process->exitCode = STILL_ACTIVE;
		process->forcedExitCode = STILL_ACTIVE;
		process->terminationRequested = false;

		return handles::allocDataHandle(handles::Data{handles::TYPE_PROCESS, (void*)process, 0});
	}

	Process* processFromHandle(void *handle, bool pop) {
		handles::Data data = handles::dataFromHandle(handle, pop);
		if (data.type == handles::TYPE_PROCESS) {
			return (Process*)data.ptr;
		} else {
			printf("Invalid file handle %p\n", handle);
			assert(0);
		}
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
		const char *delims = strchr(value.c_str(), ';') ? ";" : ":";
		size_t start = 0;
		while (start <= value.size()) {
			size_t end = value.find_first_of(delims, start);
			if (end == std::string::npos) {
				end = value.size();
			}
			std::string entry = value.substr(start, end - start);
			if (!entry.empty()) {
				bool looksWindows = entry.find('\\') != std::string::npos ||
					(entry.size() >= 2 && entry[1] == ':' && entry[0] != '/');
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
		dirs.push_back(std::filesystem::current_path());
		if (const char *envPath = std::getenv("PATH")) {
			auto parsed = parseHostPath(envPath);
			dirs.insert(dirs.end(), parsed.begin(), parsed.end());
		}
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
			std::filesystem::path parent = host.parent_path().empty() ? std::filesystem::current_path() : host.parent_path();
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

	int spawnViaWibo(const std::filesystem::path &hostExecutable, const std::vector<std::string> &arguments, pid_t *pidOut) {
		if (hostExecutable.empty()) {
			return ENOENT;
		}

		std::vector<std::string> storage;
		storage.reserve(arguments.size() + 1);
		storage.push_back(hostExecutable.string());
		for (const auto &arg : arguments) {
			storage.push_back(arg);
		}

		std::vector<char *> nativeArgs;
		nativeArgs.reserve(storage.size() + 2);
		nativeArgs.push_back(wibo::executableName);
		for (auto &entry : storage) {
			nativeArgs.push_back(entry.data());
		}
		nativeArgs.push_back(nullptr);

		posix_spawn_file_actions_t actions;
		posix_spawn_file_actions_init(&actions);

		std::string indent = std::to_string(wibo::debugIndent + 1);
		setenv("WIBO_DEBUG_INDENT", indent.c_str(), 1);

		pid_t pid = -1;
		int spawnResult = posix_spawn(&pid, wibo::executableName, &actions, nullptr, nativeArgs.data(), environ);
		posix_spawn_file_actions_destroy(&actions);
		if (spawnResult != 0) {
			return spawnResult;
		}
		if (pidOut) {
			*pidOut = pid;
		}
		return 0;
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
}
