#include "processes.h"

#include "common.h"
#include "handles.h"
#include "kernel32/internal.h"

#include <array>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <memory>
#include <shared_mutex>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <unordered_map>
#include <unistd.h>

#include <linux/sched.h>

using kernel32::ProcessObject;

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

class LinuxProcessManager final : public wibo::detail::ProcessManagerImpl {
  public:
	bool init() override;
	void shutdown() override;
	bool addProcess(Pin<ProcessObject> po) override;
	[[nodiscard]] bool running() const override { return mRunning.load(std::memory_order_acquire); }

  private:
	void runLoop();
	void wake() const;
	void checkPidfd(int pidfd);

	mutable std::shared_mutex m;
	std::atomic<bool> mRunning{false};
	std::thread mThread;
	int mEpollFd = -1;
	int mWakeFd = -1;
	std::unordered_map<int, Pin<ProcessObject>> mReg;
};

} // namespace

namespace wibo::detail {

std::unique_ptr<ProcessManagerImpl> createProcessManagerImpl() {
	return std::make_unique<LinuxProcessManager>();
}

int spawnProcess(char *const argv[], char *const envp[], SpawnProcessInfo &info) {
	pid_t pid = static_cast<pid_t>(syscall(SYS_clone, CLONE_PIDFD, nullptr, &info.pidfd));
	if (pid < 0) {
		info.pidfd = -1;
		int err = errno;
		perror("clone");
		return err;
	}
	if (pid == 0) {
		if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0) {
			perror("prctl(PR_SET_PDEATHSIG)");
		}
		execve("/proc/self/exe", argv, envp);
		perror("execve");
		_Exit(127);
	}
	info.pid = pid;
	return 0;
}

} // namespace wibo::detail

namespace {

bool epollAdd(int epollFd, int fd) {
	epoll_event ev{};
	ev.events = EPOLLIN;
	ev.data.fd = fd;
	if (epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		perror("epoll_ctl");
		return false;
	}
	return true;
}

} // namespace

bool LinuxProcessManager::init() {
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

	if (!epollAdd(mEpollFd, mWakeFd)) {
		close(mWakeFd);
		mWakeFd = -1;
		close(mEpollFd);
		mEpollFd = -1;
		return false;
	}

	mRunning.store(true, std::memory_order_release);
	mThread = std::thread(&LinuxProcessManager::runLoop, this);
	DEBUG_LOG("ProcessManager (Linux) initialized\n");
	return true;
}

void LinuxProcessManager::shutdown() {
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

bool LinuxProcessManager::addProcess(Pin<ProcessObject> po) {
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
		if (!epollAdd(mEpollFd, pidfd)) {
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

void LinuxProcessManager::runLoop() {
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
				uint64_t value;
				while (read(mWakeFd, &value, sizeof(value)) == sizeof(value)) {
				}
				continue;
			}
			checkPidfd(ev.data.fd);
		}
	}
}

void LinuxProcessManager::wake() const {
	if (mWakeFd < 0) {
		return;
	}
	uint64_t n = 1;
	ssize_t r [[maybe_unused]] = write(mWakeFd, &n, sizeof(n));
}

void LinuxProcessManager::checkPidfd(int pidfd) {
	DEBUG_LOG("ProcessManager: checking pidfd %d\n", pidfd);

	siginfo_t si{};
	si.si_code = CLD_DUMPED;
	if (pidfd >= 0) {
		int rc = waitid(P_PIDFD, pidfd, &si, WEXITED | WNOHANG);
		if (rc < 0) {
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

