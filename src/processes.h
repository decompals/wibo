#pragma once

#include "kernel32/internal.h"

#include <filesystem>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using kernel32::ProcessObject;

namespace wibo {

class ProcessManager {
  public:
	~ProcessManager();
	bool init();
	void shutdown();
	bool addProcess(Pin<ProcessObject> po);
	bool running() const { return mRunning.load(std::memory_order_acquire); }

  private:
	void runLoop();
	void wake() const;
	void checkPidfd(int pidfd);

	mutable std::shared_mutex m;
	std::atomic<bool> mRunning = false;
	std::thread mThread;
	int mEpollFd = -1;
	int mWakeFd = -1;
	std::unordered_map<int, Pin<ProcessObject>> mReg;
};

ProcessManager &processes();

std::optional<std::filesystem::path> resolveExecutable(const std::string &command, bool searchPath);
int spawnWithCommandLine(const std::string &applicationName, const std::string &commandLine,
						 Pin<kernel32::ProcessObject> &pinOut);
int spawnWithArgv(const std::string &applicationName, const std::vector<std::string> &argv,
				  Pin<kernel32::ProcessObject> &pinOut);
std::vector<std::string> splitCommandLine(const char *commandLine);

} // namespace wibo
