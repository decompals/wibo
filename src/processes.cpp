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
#include <fcntl.h>
#include <filesystem>
#include <linux/sched.h>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <spawn.h>
#include <string>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

inline DWORD decodeExitCode(const siginfo_t &si) {
	switch (si.si_code) {
	case CLD_EXITED:
		return static_cast<DWORD>(si.si_status);
	case CLD_KILLED:
	case CLD_DUMPED:
		return 0xC0000000u | static_cast<DWORD>(si.si_status);
	default:
		return 0;
	}
}

} // namespace

namespace wibo {

ProcessManager::~ProcessManager() { shutdown(); }

bool ProcessManager::init() {
	if (mRunning.load(std::memory_order_acquire)) {
		return true;
	}

	mEpollFd = epoll_create1(EPOLL_CLOEXEC);
	if (mEpollFd < 0) {
		perror("epoll_create1");
		return false;
	}

	mWakeFd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (mWakeFd < 0) {
		perror("eventfd");
		close(mEpollFd);
		mEpollFd = -1;
		return false;
	}

	epoll_event ev{};
	ev.events = EPOLLIN;
	ev.data.fd = mWakeFd;
	if (epoll_ctl(mEpollFd, EPOLL_CTL_ADD, mWakeFd, &ev) < 0) {
		perror("epoll_ctl");
		close(mWakeFd);
		mWakeFd = -1;
		close(mEpollFd);
		mEpollFd = -1;
		return false;
	}

	mRunning.store(true, std::memory_order_release);
	mThread = std::thread(&ProcessManager::runLoop, this);
	DEBUG_LOG("ProcessManager initialized\n");
	return true;
}

void ProcessManager::shutdown() {
	if (!mRunning.exchange(false, std::memory_order_acq_rel)) {
		return;
	}
	wake();
	if (mThread.joinable()) {
		mThread.join();
	}
	std::lock_guard lk(m);
	mReg.clear();
	if (mWakeFd >= 0) {
		close(mWakeFd);
		mWakeFd = -1;
	}
	if (mEpollFd >= 0) {
		close(mEpollFd);
		mEpollFd = -1;
	}
}

bool ProcessManager::addProcess(Pin<ProcessObject> po) {
	if (!po) {
		return false;
	}
	pid_t pid;
	int pidfd;
	{
		std::lock_guard lk(po->m);
		pid = po->pid;
		pidfd = po->pidfd;
		if (pidfd < 0) {
			return false;
		}

		epoll_event ev{};
		ev.events = EPOLLIN;
		ev.data.fd = pidfd;
		if (epoll_ctl(mEpollFd, EPOLL_CTL_ADD, pidfd, &ev) < 0) {
			perror("epoll_ctl");
			close(pidfd);
			po->pidfd = -1;
			return false;
		}
	}
	{
		std::lock_guard lk(m);
		mReg.emplace(pidfd, std::move(po));
	}
	DEBUG_LOG("ProcessManager: registered pid %d with pidfd %d\n", pid, pidfd);
	wake();
	return true;
}

void ProcessManager::runLoop() {
	constexpr int kMaxEvents = 64;
	std::array<epoll_event, kMaxEvents> events{};
	while (mRunning.load(std::memory_order_acquire)) {
		int n = epoll_wait(mEpollFd, events.data(), kMaxEvents, -1);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			perror("epoll_wait");
			break;
		}
		for (int i = 0; i < n; ++i) {
			const auto &ev = events[i];
			if (ev.data.fd == mWakeFd) {
				// Drain eventfd
				uint64_t n;
				while (read(mWakeFd, &n, sizeof(n)) == sizeof(n)) {
				}
				continue;
			}
			checkPidfd(ev.data.fd);
		}
	}
}

void ProcessManager::wake() const {
	if (mWakeFd < 0) {
		return;
	}
	uint64_t n = 1;
	ssize_t r [[maybe_unused]] = write(mWakeFd, &n, sizeof(n));
}

void ProcessManager::checkPidfd(int pidfd) {
	DEBUG_LOG("ProcessManager: checking pidfd %d\n", pidfd);

	siginfo_t si{};
	si.si_code = CLD_DUMPED;
	if (pidfd >= 0) {
		int rc = waitid(P_PIDFD, pidfd, &si, WEXITED | WNOHANG);
		if (rc < 0) {
			// TODO: what to do here?
			perror("waitid");
		} else if (rc == 0 && si.si_pid == 0) {
			return;
		}
		epoll_ctl(mEpollFd, EPOLL_CTL_DEL, pidfd, nullptr);
	}

	DEBUG_LOG("ProcessManager: pidfd %d exited: code=%d status=%d\n", pidfd, si.si_code, si.si_status);

	Pin<ProcessObject> po;
	{
		std::unique_lock lk(m);
		auto it = mReg.find(pidfd);
		if (it != mReg.end()) {
			po = std::move(it->second);
			mReg.erase(it);
		}
	}
	close(pidfd);
	if (!po) {
		return;
	}
	{
		std::lock_guard lk(po->m);
		po->signaled = true;
		po->pidfd = -1;
		if (!po->forcedExitCode) {
			po->exitCode = decodeExitCode(si);
		}
	}
	po->cv.notify_all();
	po->notifyWaiters(false);
}

ProcessManager &processes() {
	static ProcessManager mgr;
	if (!mgr.init()) {
		fprintf(stderr, "Failed to initialize ProcessManager\n");
		abort();
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
	const char *delims = strchr(value.c_str(), ';') ? ";" : ":";
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
	addFromEnv("WINEPATH"); // Wine compatibility
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

static int spawnClone(pid_t &pid, int &pidfd, char **argv, char **envp) {
	pid = static_cast<pid_t>(syscall(SYS_clone, CLONE_PIDFD, nullptr, &pidfd));
	if (pid < 0) {
		int err = errno;
		perror("clone");
		return err;
	} else if (pid == 0) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		execve("/proc/self/exe", argv, envp);
		// If we're still here, something went wrong
		perror("execve");
		_exit(127);
	}
	return 0;
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
		if (strncmp(*e, "WIBO_DEBUG_INDENT=", 18) != 0)
			ownedEnv.emplace_back(*e);
	}
	ownedEnv.emplace_back("WIBO_DEBUG_INDENT=" + std::to_string(wibo::debugIndent + 1));

	std::vector<char *> envp;
	envp.reserve(ownedEnv.size() + 1);
	for (auto &s : ownedEnv)
		envp.push_back(const_cast<char *>(s.c_str()));
	envp.push_back(nullptr);

	pid_t pid = -1;
	int pidfd = -1;
	int rc = spawnClone(pid, pidfd, argv.data(), envp.data());
	if (rc != 0) {
		return rc;
	}

	DEBUG_LOG("Spawned process with PID %d (pidfd=%d)\n", pid, pidfd);

	auto obj = make_pin<kernel32::ProcessObject>(pid, pidfd);
	pinOut = obj.clone();
	if (!processes().addProcess(std::move(obj))) {
		fprintf(stderr, "Failed to add process to process manager\n");
		abort();
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

} // namespace wibo
