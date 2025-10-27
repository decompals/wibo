#include "namedpipeapi.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "handles.h"
#include "internal.h"
#include "overlapped_util.h"
#include "strutil.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <condition_variable>
#include <fcntl.h>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace kernel32 {

namespace {

struct NamedPipeInstance;

void configureInheritability(int fd, bool inherit) {
	if (fd < 0) {
		return;
	}
	int flags = fcntl(fd, F_GETFD);
	if (flags == -1) {
		return;
	}
	if (inherit) {
		flags &= ~FD_CLOEXEC;
	} else {
		flags |= FD_CLOEXEC;
	}
	fcntl(fd, F_SETFD, flags);
}

struct ParsedPipeName {
	std::string key;
	std::u16string namespaceKey;
};

std::optional<ParsedPipeName> parsePipeName(LPCSTR name, DWORD &error) {
	error = ERROR_SUCCESS;
	if (!name) {
		error = ERROR_PATH_NOT_FOUND;
		return std::nullopt;
	}
	std::string_view input{name};
	if (input.empty()) {
		error = ERROR_INVALID_NAME;
		return std::nullopt;
	}
	if (input.size() > 256) {
		error = ERROR_INVALID_PARAMETER;
		return std::nullopt;
	}
	std::string lower;
	lower.reserve(input.size());
	for (char ch : input) {
		lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
	}
	constexpr std::string_view kLocalPrefix = "\\\\.\\pipe\\";
	constexpr std::string_view kNtPrefix = "\\\\?\\pipe\\";
	size_t prefixLen = 0;
	if (lower.rfind(kLocalPrefix, 0) == 0) {
		prefixLen = kLocalPrefix.size();
	} else if (lower.rfind(kNtPrefix, 0) == 0) {
		prefixLen = kNtPrefix.size();
	} else {
		// Not a pipe path; treat as non-match without error.
		return std::nullopt;
	}
	std::string raw = std::string(input.substr(prefixLen));
	if (raw.empty()) {
		error = ERROR_INVALID_HANDLE;
		return std::nullopt;
	}
	if (raw.find('\\') != std::string::npos || raw.find('/') != std::string::npos) {
		error = ERROR_INVALID_NAME;
		return std::nullopt;
	}
	std::string key = lower.substr(prefixLen);
	return ParsedPipeName{std::move(key), stringToUtf16(lower.substr(prefixLen))};
}

DWORD normalizeMaxInstances(DWORD value) {
	if (value == 0) {
		return 1;
	}
	if (value >= PIPE_UNLIMITED_INSTANCES) {
		return PIPE_UNLIMITED_INSTANCES;
	}
	return value;
}

struct NamedPipeState : ObjectBase {
	static constexpr ObjectType kType = ObjectType::NamedPipeState;

	std::mutex mutex;
	std::string key;
	DWORD accessMode = PIPE_ACCESS_DUPLEX;
	DWORD pipeType = PIPE_TYPE_BYTE;
	DWORD defaultTimeout = 0;
	DWORD maxInstances = PIPE_UNLIMITED_INSTANCES;
	uint32_t instanceCount = 0;
	std::vector<NamedPipeInstance *> instances;

	explicit NamedPipeState(std::string k) : ObjectBase(kType), key(std::move(k)) {}
	~NamedPipeState() override { wibo::g_namespace.remove(this); }

	void registerInstance(NamedPipeInstance *inst) {
		std::lock_guard lk(mutex);
		instances.push_back(inst);
	}

	void unregisterInstance(NamedPipeInstance *inst) {
		std::lock_guard lk(mutex);
		auto it = std::find(instances.begin(), instances.end(), inst);
		if (it != instances.end()) {
			instances.erase(it);
		}
	}

	bool reserveInstance(DWORD access, DWORD type, DWORD timeout, DWORD maxAllowed, bool firstFlag, bool isNew,
						 DWORD &error) {
		error = ERROR_SUCCESS;
		std::lock_guard lk(mutex);
		if (isNew) {
			accessMode = access;
			pipeType = type;
			defaultTimeout = timeout;
			maxInstances = maxAllowed;
		} else {
			if (accessMode != access || pipeType != type || defaultTimeout != timeout) {
				error = ERROR_ACCESS_DENIED;
				return false;
			}
			if (maxInstances != maxAllowed) {
				error = ERROR_ACCESS_DENIED;
				return false;
			}
		}
		if (firstFlag && instanceCount > 0) {
			error = ERROR_ACCESS_DENIED;
			return false;
		}
		if (maxInstances != PIPE_UNLIMITED_INSTANCES && instanceCount >= maxInstances) {
			error = ERROR_PIPE_BUSY;
			return false;
		}
		++instanceCount;
		return true;
	}

	bool releaseInstance() {
		std::lock_guard lk(mutex);
		if (instanceCount > 0) {
			--instanceCount;
		}
		return instanceCount == 0;
	}
};

struct NamedPipeInstance final : FileObject {
	static constexpr ObjectType kType = ObjectType::NamedPipe;

	Pin<NamedPipeState> state;
	int companionFd = -1;
	DWORD accessMode;
	DWORD pipeMode;
	bool clientConnected = false;
	bool connectPending = false;
	LPOVERLAPPED pendingOverlapped = nullptr;
	std::mutex connectMutex;
	std::condition_variable connectCv;

	NamedPipeInstance(int fd, Pin<NamedPipeState> st, int companion, DWORD open, DWORD mode)
		: FileObject(kType, fd), state(std::move(st)), companionFd(companion), accessMode(open), pipeMode(mode) {
		if (state) {
			state->registerInstance(this);
		}
	}

	~NamedPipeInstance() override {
		int localCompanion = -1;
		{
			std::lock_guard lk(connectMutex);
			localCompanion = companionFd;
			companionFd = -1;
			kernel32::detail::signalOverlappedEvent(this, pendingOverlapped, STATUS_PIPE_BROKEN, 0);
			pendingOverlapped = nullptr;
			connectPending = false;
			connectCv.notify_all();
		}
		if (localCompanion >= 0) {
			close(localCompanion);
		}
		if (state) {
			state->unregisterInstance(this);
			state->releaseInstance();
		}
	}

	bool canAcceptClient(DWORD desiredAccess) {
		std::lock_guard lk(connectMutex);
		if (companionFd < 0 || clientConnected) {
			return false;
		}
		DWORD access = accessMode & PIPE_ACCESS_DUPLEX;
		switch (access) {
		case PIPE_ACCESS_DUPLEX:
			return (desiredAccess & (GENERIC_READ | GENERIC_WRITE)) != 0;
		case PIPE_ACCESS_INBOUND:
			return (desiredAccess & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA)) != 0;
		case PIPE_ACCESS_OUTBOUND:
			return (desiredAccess & (GENERIC_READ | FILE_READ_DATA)) != 0;
		default:
			return false;
		}
	}

	int takeCompanion() {
		std::lock_guard lk(connectMutex);
		if (companionFd < 0 || clientConnected) {
			return -1;
		}
		int fd = companionFd;
		companionFd = -1;
		clientConnected = true;
		kernel32::detail::signalOverlappedEvent(this, pendingOverlapped, STATUS_SUCCESS, 0);
		pendingOverlapped = nullptr;
		if (connectPending) {
			connectPending = false;
			connectCv.notify_all();
		}
		return fd;
	}

	void restoreCompanion(int fd) {
		std::lock_guard lk(connectMutex);
		companionFd = fd;
		if (fd >= 0) {
			clientConnected = false;
		}
	}
};

Pin<NamedPipeInstance> acquireConnectableInstance(Pin<NamedPipeState> &state, DWORD desiredAccess, DWORD &error) {
	if (!state) {
		error = ERROR_FILE_NOT_FOUND;
		return {};
	}
	std::lock_guard lk(state->mutex);
	for (auto *inst : state->instances) {
		if (!inst) {
			continue;
		}
		if (inst->canAcceptClient(desiredAccess)) {
			return Pin<NamedPipeInstance>::acquire(inst);
		}
	}
	error = ERROR_PIPE_BUSY;
	return {};
}

} // namespace

bool tryCreateFileNamedPipeA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
							 LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
							 DWORD dwFlagsAndAttributes, HANDLE &outHandle) {
	(void)dwShareMode;
	(void)dwCreationDisposition;

	DWORD parseError = ERROR_SUCCESS;
	auto parsed = parsePipeName(lpFileName, parseError);
	if (!parsed) {
		if (parseError != ERROR_SUCCESS) {
			wibo::lastError = parseError;
			outHandle = INVALID_HANDLE_VALUE;
			return true;
		}
		return false;
	}

	auto state = wibo::g_namespace.getAs<NamedPipeState>(parsed->namespaceKey);
	if (!state) {
		wibo::lastError = ERROR_FILE_NOT_FOUND;
		outHandle = INVALID_HANDLE_VALUE;
		return true;
	}

	DWORD acquireError = ERROR_SUCCESS;
	auto instancePin = acquireConnectableInstance(state, dwDesiredAccess, acquireError);
	if (!instancePin) {
		wibo::lastError = acquireError;
		outHandle = INVALID_HANDLE_VALUE;
		return true;
	}

	int clientFd = instancePin->takeCompanion();
	if (clientFd < 0) {
		wibo::lastError = ERROR_PIPE_BUSY;
		outHandle = INVALID_HANDLE_VALUE;
		return true;
	}

	bool inherit = lpSecurityAttributes && lpSecurityAttributes->bInheritHandle;
	configureInheritability(clientFd, inherit);

	auto clientObj = make_pin<FileObject>(clientFd);
	if (!clientObj) {
		instancePin->restoreCompanion(clientFd);
		wibo::lastError = ERROR_NOT_ENOUGH_MEMORY;
		outHandle = INVALID_HANDLE_VALUE;
		return true;
	}
	clientFd = -1;

	clientObj->shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
	clientObj->overlapped = (dwFlagsAndAttributes & FILE_FLAG_OVERLAPPED) != 0;

	uint32_t grantedAccess = SYNCHRONIZE;
	switch (instancePin->accessMode & PIPE_ACCESS_DUPLEX) {
	case PIPE_ACCESS_DUPLEX:
		grantedAccess |= FILE_GENERIC_READ | FILE_GENERIC_WRITE;
		break;
	case PIPE_ACCESS_INBOUND:
		grantedAccess |= FILE_GENERIC_WRITE;
		break;
	case PIPE_ACCESS_OUTBOUND:
		grantedAccess |= FILE_GENERIC_READ;
		break;
	default:
		break;
	}

	uint32_t handleFlags = inherit ? HANDLE_FLAG_INHERIT : 0;
	outHandle = wibo::handles().alloc(std::move(clientObj), grantedAccess, handleFlags);
	return true;
}

BOOL WIN_FUNC CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CreatePipe(%p, %p, %p, %u)\n", hReadPipe, hWritePipe, lpPipeAttributes, nSize);
	if (!hReadPipe || !hWritePipe) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	*hReadPipe = nullptr;
	*hWritePipe = nullptr;

	int pipeFds[2];
	if (pipe(pipeFds) != 0) {
		setLastErrorFromErrno();
		return FALSE;
	}

	bool inheritHandles = lpPipeAttributes && lpPipeAttributes->bInheritHandle;
	configureInheritability(pipeFds[0], inheritHandles);
	configureInheritability(pipeFds[1], inheritHandles);

	if (nSize != 0) {
		// Best-effort adjustment; ignore failures as recommended by docs.
		fcntl(pipeFds[0], F_SETPIPE_SZ, static_cast<int>(nSize));
		fcntl(pipeFds[1], F_SETPIPE_SZ, static_cast<int>(nSize));
	}

	auto readObj = make_pin<FileObject>(pipeFds[0]);
	readObj->shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
	auto writeObj = make_pin<FileObject>(pipeFds[1]);
	writeObj->shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
	*hReadPipe = wibo::handles().alloc(std::move(readObj), FILE_GENERIC_READ, 0);
	*hWritePipe = wibo::handles().alloc(std::move(writeObj), FILE_GENERIC_WRITE, 0);
	return TRUE;
}

HANDLE WIN_FUNC CreateNamedPipeA(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances,
								 DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut,
								 LPSECURITY_ATTRIBUTES lpSecurityAttributes) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("CreateNamedPipeA(%s, 0x%08x, 0x%08x, %u, %u, %u, %u, %p)\n", lpName ? lpName : "(null)", dwOpenMode,
			  dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);

	DWORD parseError = ERROR_SUCCESS;
	std::optional<ParsedPipeName> parsed = parsePipeName(lpName, parseError);
	if (!parsed) {
		wibo::lastError = (parseError == ERROR_SUCCESS) ? ERROR_INVALID_NAME : parseError;
		return INVALID_HANDLE_VALUE;
	}

	constexpr DWORD kAllowedOpenFlags = PIPE_ACCESS_DUPLEX | WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY |
										FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OVERLAPPED;
	if ((dwOpenMode & ~kAllowedOpenFlags) != 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return INVALID_HANDLE_VALUE;
	}

	DWORD accessMode = dwOpenMode & PIPE_ACCESS_DUPLEX;
	if (accessMode != PIPE_ACCESS_DUPLEX && accessMode != PIPE_ACCESS_INBOUND && accessMode != PIPE_ACCESS_OUTBOUND) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return INVALID_HANDLE_VALUE;
	}

	const bool firstInstanceFlag = (dwOpenMode & FILE_FLAG_FIRST_PIPE_INSTANCE) != 0;
	const bool inheritHandles = lpSecurityAttributes && lpSecurityAttributes->bInheritHandle;
	const bool overlapped = (dwOpenMode & FILE_FLAG_OVERLAPPED) != 0;

	constexpr DWORD kAllowedPipeModeFlags =
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS;
	if ((dwPipeMode & ~kAllowedPipeModeFlags) != 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return INVALID_HANDLE_VALUE;
	}
	if ((dwPipeMode & PIPE_READMODE_MESSAGE) != 0 && (dwPipeMode & PIPE_TYPE_MESSAGE) == 0) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return INVALID_HANDLE_VALUE;
	}

	DWORD pipeType = (dwPipeMode & PIPE_TYPE_MESSAGE) != 0 ? PIPE_TYPE_MESSAGE : PIPE_TYPE_BYTE;
	DWORD normalizedMaxInstances = normalizeMaxInstances(nMaxInstances);

	auto [state, isNewState] = wibo::g_namespace.getOrCreate(
		parsed->namespaceKey, [&]() -> NamedPipeState * { return new NamedPipeState(parsed->key); });
	if (!state) {
		wibo::lastError = ERROR_NOT_ENOUGH_MEMORY;
		return INVALID_HANDLE_VALUE;
	}

	bool instanceReserved = false;
	DWORD reserveError = ERROR_SUCCESS;
	if (!state->reserveInstance(accessMode, pipeType, nDefaultTimeOut, normalizedMaxInstances, firstInstanceFlag,
								isNewState, reserveError)) {
		wibo::lastError = reserveError;
		return INVALID_HANDLE_VALUE;
	}
	instanceReserved = true;

	int serverFd = -1;
	int companionFd = -1;
	auto fail = [&](DWORD err) -> HANDLE {
		if (serverFd >= 0) {
			close(serverFd);
			serverFd = -1;
		}
		if (companionFd >= 0) {
			close(companionFd);
			companionFd = -1;
		}
		if (instanceReserved && state) {
			state->releaseInstance();
			instanceReserved = false;
		}
		wibo::lastError = err;
		return INVALID_HANDLE_VALUE;
	};

	int fds[2] = {-1, -1};
	if (accessMode == PIPE_ACCESS_DUPLEX) {
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
			int savedErrno = errno;
			return fail(wibo::winErrorFromErrno(savedErrno));
		}
		serverFd = fds[0];
		companionFd = fds[1];
	} else {
		if (pipe(fds) != 0) {
			int savedErrno = errno;
			return fail(wibo::winErrorFromErrno(savedErrno));
		}
		if (accessMode == PIPE_ACCESS_INBOUND) {
			serverFd = fds[0];
			companionFd = fds[1];
			if (nInBufferSize != 0) {
				fcntl(serverFd, F_SETPIPE_SZ, static_cast<int>(nInBufferSize));
			}
		} else {
			serverFd = fds[1];
			companionFd = fds[0];
			if (nOutBufferSize != 0) {
				fcntl(serverFd, F_SETPIPE_SZ, static_cast<int>(nOutBufferSize));
			}
		}
	}

	configureInheritability(serverFd, inheritHandles);
	if (companionFd >= 0) {
		configureInheritability(companionFd, inheritHandles);
	}

	auto pipeObj = make_pin<NamedPipeInstance>(serverFd, std::move(state), companionFd, accessMode, dwPipeMode);
	if (!pipeObj) {
		return fail(ERROR_NOT_ENOUGH_MEMORY);
	}
	serverFd = -1;
	companionFd = -1;
	instanceReserved = false;

	pipeObj->shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
	pipeObj->overlapped = overlapped;

	uint32_t grantedAccess = SYNCHRONIZE;
	switch (accessMode) {
	case PIPE_ACCESS_DUPLEX:
		grantedAccess |= FILE_GENERIC_READ | FILE_GENERIC_WRITE;
		break;
	case PIPE_ACCESS_INBOUND:
		grantedAccess |= FILE_GENERIC_READ;
		break;
	case PIPE_ACCESS_OUTBOUND:
		grantedAccess |= FILE_GENERIC_WRITE;
		break;
	default:
		break;
	}

	uint32_t handleFlags = inheritHandles ? HANDLE_FLAG_INHERIT : 0;
	return wibo::handles().alloc(std::move(pipeObj), grantedAccess, handleFlags);
}

BOOL WIN_FUNC ConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("ConnectNamedPipe(%p, %p)\n", hNamedPipe, lpOverlapped);

	auto pipe = wibo::handles().getAs<NamedPipeInstance>(hNamedPipe);
	if (!pipe) {
		wibo::lastError = ERROR_INVALID_HANDLE;
		return FALSE;
	}

	const bool isOverlappedHandle = pipe->overlapped;
	if (isOverlappedHandle && lpOverlapped == nullptr) {
		wibo::lastError = ERROR_INVALID_PARAMETER;
		return FALSE;
	}

	std::unique_lock lock(pipe->connectMutex);

	if (pipe->clientConnected) {
		wibo::lastError = ERROR_PIPE_CONNECTED;
		return FALSE;
	}

	if (pipe->companionFd < 0) {
		wibo::lastError = ERROR_PIPE_BUSY;
		return FALSE;
	}

	if (pipe->connectPending) {
		wibo::lastError = ERROR_PIPE_LISTENING;
		return FALSE;
	}

	if ((pipe->pipeMode & PIPE_NOWAIT) != 0) {
		wibo::lastError = ERROR_PIPE_LISTENING;
		return FALSE;
	}

	if (isOverlappedHandle) {
		pipe->connectPending = true;
		pipe->pendingOverlapped = lpOverlapped;
		lpOverlapped->Internal = STATUS_PENDING;
		lpOverlapped->InternalHigh = 0;
		kernel32::detail::resetOverlappedEvent(lpOverlapped);
		lock.unlock();
		wibo::lastError = ERROR_IO_PENDING;
		return FALSE;
	}

	pipe->connectPending = true;
	pipe->connectCv.wait(lock, [&]() { return pipe->clientConnected || pipe->companionFd < 0; });
	pipe->connectPending = false;
	if (!pipe->clientConnected) {
		wibo::lastError = ERROR_NO_DATA;
		return FALSE;
	}
	return TRUE;
}

} // namespace kernel32
