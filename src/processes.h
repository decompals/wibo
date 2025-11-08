#pragma once

#include "kernel32/internal.h"

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using kernel32::ProcessObject;

namespace wibo {

namespace detail {

class ProcessManagerImpl {
  public:
	virtual ~ProcessManagerImpl() = default;
	virtual bool init() = 0;
	virtual void shutdown() = 0;
	virtual bool addProcess(Pin<ProcessObject> po) = 0;
	[[nodiscard]] virtual bool running() const = 0;
};

struct SpawnProcessInfo {
	pid_t pid = -1;
	int pidfd = -1;
};

std::unique_ptr<ProcessManagerImpl> createProcessManagerImpl();
int spawnProcess(char *const argv[], char *const envp[], SpawnProcessInfo &info);

} // namespace detail

class ProcessManager {
  public:
	ProcessManager();
	~ProcessManager();
	bool init();
	void shutdown();
	bool addProcess(Pin<ProcessObject> po);
	[[nodiscard]] bool running() const;

  private:
	std::unique_ptr<detail::ProcessManagerImpl> mImpl;
};

ProcessManager &processes();

std::optional<std::filesystem::path> resolveExecutable(const std::string &command, bool searchPath);
int spawnWithCommandLine(const std::string &applicationName, const std::string &commandLine,
						 Pin<kernel32::ProcessObject> &pinOut);
int spawnWithArgv(const std::string &applicationName, const std::vector<std::string> &argv,
				  Pin<kernel32::ProcessObject> &pinOut);
std::vector<std::string> splitCommandLine(const char *commandLine);

} // namespace wibo
