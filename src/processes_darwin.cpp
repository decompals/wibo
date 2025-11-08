#include "processes.h"

#include "common.h"
#include "handles.h"
#include "kernel32/internal.h"

#include <array>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <spawn.h>
#include <system_error>
#include <string>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <thread>
#include <unordered_map>
#include <unistd.h>

#define ENUM_DYLD_BOOL
#include <mach-o/dyld.h>

using kernel32::ProcessObject;

namespace {

DWORD decodeExitStatus(int status) {
	if (WIFEXITED(status)) {
		return static_cast<DWORD>(WEXITSTATUS(status));
	}
	if (WIFSIGNALED(status)) {
		return 0xC0000000u | static_cast<DWORD>(WTERMSIG(status));
	}
	return 0;
}

std::string &executablePath() {
	static std::string path;
	static std::once_flag once;
	std::call_once(once, [] {
		uint32_t size = 0;
		if (_NSGetExecutablePath(nullptr, &size) != 0 && size > 0) {
			std::string buffer(size, '\0');
			if (_NSGetExecutablePath(buffer.data(), &size) == 0) {
				std::error_code ec;
				auto canonical = std::filesystem::weakly_canonical(buffer.c_str(), ec);
				if (!ec) {
					path = canonical.string();
				} else {
					path.assign(buffer.c_str());
				}
			}
		}
		if (path.empty()) {
			path = "wibo";
		}
	});
	return path;
}

class DarwinProcessManager final : public wibo::detail::ProcessManagerImpl {
  public:
	bool init() override;
	void shutdown() override;
	bool addProcess(Pin<ProcessObject> po) override;
	[[nodiscard]] bool running() const override { return mRunning.load(std::memory_order_acquire); }

  private:
	void runLoop();
	void wake() const;
	void handleExit(pid_t pid);

	mutable std::shared_mutex m;
	std::atomic<bool> mRunning{false};
	std::thread mThread;
	int mKqueueFd = -1;
	uintptr_t mWakeIdent = 1;
	std::unordered_map<pid_t, Pin<ProcessObject>> mReg;
};

} // namespace

namespace wibo::detail {

std::unique_ptr<ProcessManagerImpl> createProcessManagerImpl() {
	return std::make_unique<DarwinProcessManager>();
}

int spawnProcess(char *const argv[], char *const envp[], SpawnProcessInfo &info) {
	auto &path = executablePath();
	posix_spawnattr_t attr;
	int rc = posix_spawnattr_init(&attr);
	if (rc != 0) {
		return rc;
	}
	sigset_t mask;
	sigemptyset(&mask);
	rc = posix_spawnattr_setsigmask(&attr, &mask);
	if (rc == 0) {
		rc = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK);
	}
	pid_t pid = -1;
	if (rc == 0) {
		rc = posix_spawn(&pid, path.c_str(), nullptr, &attr, argv, envp);
	}
	posix_spawnattr_destroy(&attr);
	if (rc != 0) {
		return rc;
	}
	info.pid = pid;
	info.pidfd = -1;
	return 0;
}

} // namespace wibo::detail

bool DarwinProcessManager::init() {
	if (mRunning.load(std::memory_order_acquire)) {
		return true;
	}

	mKqueueFd = kqueue();
	if (mKqueueFd < 0) {
		perror("kqueue");
		return false;
	}

	struct kevent kev;
	EV_SET(&kev, mWakeIdent, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, nullptr);
	if (kevent(mKqueueFd, &kev, 1, nullptr, 0, nullptr) < 0) {
		perror("kevent(EV_ADD user)");
		close(mKqueueFd);
		mKqueueFd = -1;
		return false;
	}

	mRunning.store(true, std::memory_order_release);
	mThread = std::thread(&DarwinProcessManager::runLoop, this);
	DEBUG_LOG("ProcessManager (Darwin) initialized\n");
	return true;
}

void DarwinProcessManager::shutdown() {
	if (!mRunning.exchange(false, std::memory_order_acq_rel)) {
		return;
	}
	wake();
	if (mThread.joinable()) {
		mThread.join();
	}
	std::lock_guard lk(m);
	mReg.clear();
	if (mKqueueFd >= 0) {
		close(mKqueueFd);
		mKqueueFd = -1;
	}
}

bool DarwinProcessManager::addProcess(Pin<ProcessObject> po) {
	if (!po) {
		return false;
	}
	pid_t pid;
	{
		std::lock_guard lk(po->m);
		pid = po->pid;
	}
	struct kevent kev;
	EV_SET(&kev, static_cast<uintptr_t>(pid), EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT | NOTE_EXITSTATUS, 0, nullptr);
	if (kevent(mKqueueFd, &kev, 1, nullptr, 0, nullptr) < 0) {
		int err = errno;
		DEBUG_LOG("ProcessManager: kevent add for pid %d failed: %s\n", pid, strerror(err));
		if (err == ESRCH) {
			int status = 0;
			pid_t waited = waitpid(pid, &status, WNOHANG);
			if (waited <= 0) {
				waitpid(pid, &status, 0);
			}
			{
				std::lock_guard lk(po->m);
				po->signaled = true;
				po->pidfd = -1;
				if (!po->forcedExitCode) {
					po->exitCode = decodeExitStatus(status);
				}
			}
			po->cv.notify_all();
			po->notifyWaiters(false);
			return true;
		}
		return false;
	}
	{
		std::lock_guard lk(m);
		mReg.emplace(pid, std::move(po));
	}
	DEBUG_LOG("ProcessManager: registered pid %d\n", pid);
	wake();
	return true;
}

void DarwinProcessManager::runLoop() {
	constexpr int kMaxEvents = 64;
	std::array<struct kevent, kMaxEvents> events{};
	while (mRunning.load(std::memory_order_acquire)) {
		int n = kevent(mKqueueFd, nullptr, 0, events.data(), kMaxEvents, nullptr);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			perror("kevent");
			break;
		}
		for (int i = 0; i < n; ++i) {
			const auto &ev = events[i];
			if (ev.filter == EVFILT_USER) {
				continue;
			}
			if (ev.filter == EVFILT_PROC && (ev.fflags & NOTE_EXIT)) {
				handleExit(static_cast<pid_t>(ev.ident));
			}
		}
	}
}

void DarwinProcessManager::wake() const {
	if (mKqueueFd < 0) {
		return;
	}
	struct kevent kev;
	EV_SET(&kev, mWakeIdent, EVFILT_USER, 0, NOTE_TRIGGER, 0, nullptr);
	kevent(mKqueueFd, &kev, 1, nullptr, 0, nullptr);
}

void DarwinProcessManager::handleExit(pid_t pid) {
	Pin<ProcessObject> po;
	{
		std::unique_lock lk(m);
		auto it = mReg.find(pid);
		if (it != mReg.end()) {
			po = std::move(it->second);
			mReg.erase(it);
		}
	}
	if (!po) {
		// Might be a race with registration; still ensure we reap the child.
		int status = 0;
		waitpid(pid, &status, WNOHANG);
		return;
	}
	int status = 0;
	pid_t waited = waitpid(pid, &status, WNOHANG);
	if (waited == 0) {
		// Child still around; block to reap.
		waited = waitpid(pid, &status, 0);
	}
	if (waited < 0) {
		int err = errno;
		DEBUG_LOG("ProcessManager: waitpid(%d) failed: %s\n", pid, strerror(err));
		status = 0;
	}
	{
		std::lock_guard lk(po->m);
		po->signaled = true;
		po->pidfd = -1;
		if (!po->forcedExitCode) {
			po->exitCode = decodeExitStatus(status);
		}
	}
	po->cv.notify_all();
	po->notifyWaiters(false);
}
