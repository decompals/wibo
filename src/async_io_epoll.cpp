#include "async_io.h"

#include "errors.h"
#include "files.h"
#include "kernel32/overlapped_util.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <unordered_map>
#include <vector>

#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

namespace {

constexpr NTSTATUS kStatusCancelled = static_cast<NTSTATUS>(0xC0000120);

struct AsyncRequest {
	enum class Kind { Read, Write };

	Kind kind;
	Pin<kernel32::FileObject> file;
	OVERLAPPED *overlapped = nullptr;
	std::optional<off_t> offset;
	bool isPipe = false;
	bool updateFilePointer = false;
	void *readBuffer = nullptr;
	const uint8_t *writeBuffer = nullptr;
	size_t length = 0;
	size_t progress = 0;
};

struct FileState {
	explicit FileState(int fdIn) : fd(fdIn) {}

	int fd;
	bool registered = false;
	uint32_t events = 0;
	int originalFlags = -1;
	std::deque<std::unique_ptr<AsyncRequest>> readQueue;
	std::deque<std::unique_ptr<AsyncRequest>> writeQueue;
};

struct ProcessResult {
	bool completed = false;
	bool requeue = false;
	NTSTATUS status = STATUS_SUCCESS;
	size_t bytesTransferred = 0;
};

struct Completion {
	std::unique_ptr<AsyncRequest> req;
	NTSTATUS status = STATUS_SUCCESS;
	size_t bytesTransferred = 0;
};

class EpollBackend : public wibo::AsyncIOBackend {
  public:
	~EpollBackend() override { shutdown(); }

	bool init() override;
	void shutdown() override;
	[[nodiscard]] bool running() const noexcept override { return mRunning.load(std::memory_order_acquire); }

	bool queueRead(Pin<kernel32::FileObject> file, OVERLAPPED *ov, void *buffer, DWORD length,
				   const std::optional<off_t> &offset, bool isPipe) override;
	bool queueWrite(Pin<kernel32::FileObject> file, OVERLAPPED *ov, const void *buffer, DWORD length,
					const std::optional<off_t> &offset, bool isPipe) override;

  private:
	bool enqueueRequest(std::unique_ptr<AsyncRequest> req);
	bool enqueueFileRequest(std::unique_ptr<AsyncRequest> req);
	void workerLoop();
	void fileWorkerLoop();
	void handleFileEvents(FileState &state, uint32_t events);
	void notifyWorker() const;
	void drainEventFd() const;
	void updateRegistrationLocked(FileState &state) const;
	static void ensureNonBlocking(FileState &state);
	static void restoreOriginalFlags(FileState &state);
	void processCompletions();
	void failAllPending();
	void completeRequest(const AsyncRequest &req, NTSTATUS status, size_t bytesTransferred);
	static Completion processBlockingRequest(AsyncRequest &req);

	static ProcessResult tryProcessPipeRead(AsyncRequest &req);
	static ProcessResult tryProcessPipeWrite(AsyncRequest &req);

	std::atomic<bool> mRunning{false};
	std::atomic<uint32_t> mPending{0};
	int mEpollFd = -1;
	int mEventFd = -1;
	std::thread mThread;

	std::mutex mMutex;
	std::unordered_map<int, std::unique_ptr<FileState>> mFileStates;

	std::mutex mFileQueueMutex;
	std::condition_variable mFileQueueCv;
	std::deque<std::unique_ptr<AsyncRequest>> mFileQueue;
	bool mFileStopping = false;
	std::vector<std::thread> mFileWorkers;

	std::mutex mCompletionMutex;
	std::deque<Completion> mCompletions;
};

bool EpollBackend::init() {
	if (mRunning.load(std::memory_order_acquire)) {
		return true;
	}

	mEpollFd = epoll_create1(EPOLL_CLOEXEC);
	if (mEpollFd < 0) {
		DEBUG_LOG("AsyncIO(epoll): epoll_create1 failed: %d\n", errno);
		return false;
	}

	mEventFd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (mEventFd < 0) {
		DEBUG_LOG("AsyncIO(epoll): eventfd failed: %d\n", errno);
		close(mEpollFd);
		mEpollFd = -1;
		return false;
	}

	struct epoll_event event{};
	event.events = EPOLLIN;
	event.data.fd = mEventFd;
	if (epoll_ctl(mEpollFd, EPOLL_CTL_ADD, mEventFd, &event) != 0) {
		DEBUG_LOG("AsyncIO(epoll): epoll_ctl add eventfd failed: %d\n", errno);
		close(mEventFd);
		close(mEpollFd);
		mEventFd = -1;
		mEpollFd = -1;
		return false;
	}

	unsigned int workerCount = std::thread::hardware_concurrency();
	if (workerCount == 0) {
		workerCount = 1;
	}
	workerCount = std::min(workerCount, 4u);

	{
		std::lock_guard lk(mFileQueueMutex);
		mFileStopping = false;
	}
	mFileWorkers.reserve(workerCount);
	for (unsigned int i = 0; i < workerCount; ++i) {
		mFileWorkers.emplace_back(&EpollBackend::fileWorkerLoop, this);
	}

	mRunning.store(true, std::memory_order_release);
	mThread = std::thread(&EpollBackend::workerLoop, this);
	DEBUG_LOG("AsyncIO: epoll backend initialized\n");
	return true;
}

void EpollBackend::shutdown() {
	if (!mRunning.exchange(false, std::memory_order_acq_rel)) {
		return;
	}

	{
		std::lock_guard lk(mFileQueueMutex);
		mFileStopping = true;
	}
	mFileQueueCv.notify_all();
	notifyWorker();

	if (mThread.joinable()) {
		mThread.join();
	}

	for (auto &worker : mFileWorkers) {
		if (worker.joinable()) {
			worker.join();
		}
	}
	mFileWorkers.clear();

	if (mEventFd >= 0) {
		close(mEventFd);
		mEventFd = -1;
	}
	if (mEpollFd >= 0) {
		close(mEpollFd);
		mEpollFd = -1;
	}

	{
		std::lock_guard lk(mMutex);
		for (auto &entry : mFileStates) {
			restoreOriginalFlags(*entry.second);
		}
		mFileStates.clear();
	}
	{
		std::lock_guard lk(mFileQueueMutex);
		mFileQueue.clear();
	}
	{
		std::lock_guard lk(mCompletionMutex);
		mCompletions.clear();
	}
	mPending.store(0, std::memory_order_release);
}

bool EpollBackend::queueRead(Pin<kernel32::FileObject> file, OVERLAPPED *ov, void *buffer, DWORD length,
							 const std::optional<off_t> &offset, bool isPipe) {
	auto req = std::make_unique<AsyncRequest>(AsyncRequest::Kind::Read);
	req->file = std::move(file);
	req->overlapped = ov;
	req->offset = offset;
	req->isPipe = isPipe;
	req->updateFilePointer = req->file ? !req->file->overlapped : true;
	req->readBuffer = buffer;
	req->length = length;
	return enqueueRequest(std::move(req));
}

bool EpollBackend::queueWrite(Pin<kernel32::FileObject> file, OVERLAPPED *ov, const void *buffer, DWORD length,
							  const std::optional<off_t> &offset, bool isPipe) {
	auto req = std::make_unique<AsyncRequest>(AsyncRequest::Kind::Write);
	req->file = std::move(file);
	req->overlapped = ov;
	req->offset = offset;
	req->isPipe = isPipe;
	req->updateFilePointer = req->file ? !req->file->overlapped : true;
	req->writeBuffer = static_cast<const uint8_t *>(buffer);
	req->length = length;
	return enqueueRequest(std::move(req));
}

bool EpollBackend::enqueueRequest(std::unique_ptr<AsyncRequest> req) {
	if (!req || !req->file || !req->file->valid()) {
		return false;
	}
	if (!mRunning.load(std::memory_order_acquire)) {
		return false;
	}

	if (req->isPipe) {
		std::lock_guard lk(mMutex);
		if (!mRunning.load(std::memory_order_acquire)) {
			return false;
		}
		mPending.fetch_add(1, std::memory_order_acq_rel);
		const int fd = req->file->fd;
		auto &statePtr = mFileStates[fd];
		if (!statePtr) {
			statePtr = std::make_unique<FileState>(fd);
		}
		FileState &state = *statePtr;
		ensureNonBlocking(state);
		if (req->kind == AsyncRequest::Kind::Read) {
			state.readQueue.emplace_back(std::move(req));
		} else {
			state.writeQueue.emplace_back(std::move(req));
		}
		updateRegistrationLocked(state);
		notifyWorker();
		return true;
	}

	mPending.fetch_add(1, std::memory_order_acq_rel);
	if (enqueueFileRequest(std::move(req))) {
		return true;
	}
	mPending.fetch_sub(1, std::memory_order_acq_rel);
	return false;
}

bool EpollBackend::enqueueFileRequest(std::unique_ptr<AsyncRequest> req) {
	std::lock_guard lk(mFileQueueMutex);
	if (mFileStopping) {
		return false;
	}
	mFileQueue.emplace_back(std::move(req));
	mFileQueueCv.notify_one();
	return true;
}

void EpollBackend::workerLoop() {
	std::array<struct epoll_event, 128> events{};

	while (true) {
		processCompletions();

		if (!mRunning.load(std::memory_order_acquire) && mPending.load(std::memory_order_acquire) == 0) {
			break;
		}

		int timeout = mRunning.load(std::memory_order_acquire) ? -1 : 10;
		int count = epoll_wait(mEpollFd, events.data(), static_cast<int>(events.size()), timeout);
		if (count < 0) {
			if (errno == EINTR) {
				continue;
			}
			DEBUG_LOG("AsyncIO(epoll): epoll_wait failed: %d\n", errno);
			continue;
		}
		if (count == 0) {
			continue;
		}

		for (int i = 0; i < count; ++i) {
			auto &ev = events[static_cast<size_t>(i)];
			if (ev.data.fd == mEventFd) {
				drainEventFd();
				processCompletions();
				continue;
			}
			if (auto *state = static_cast<FileState *>(ev.data.ptr)) {
				handleFileEvents(*state, ev.events);
			}
		}
	}

	processCompletions();
	failAllPending();
}

void EpollBackend::fileWorkerLoop() {
	while (true) {
		std::unique_ptr<AsyncRequest> req;
		{
			std::unique_lock lk(mFileQueueMutex);
			mFileQueueCv.wait(lk, [&] { return mFileStopping || !mFileQueue.empty(); });
			if (mFileStopping && mFileQueue.empty()) {
				break;
			}
			req = std::move(mFileQueue.front());
			mFileQueue.pop_front();
		}

		if (!req) {
			continue;
		}

		Completion completion = processBlockingRequest(*req);
		completion.req = std::move(req);
		{
			std::lock_guard lk(mCompletionMutex);
			mCompletions.emplace_back(std::move(completion));
		}
		notifyWorker();
	}
}

void EpollBackend::handleFileEvents(FileState &state, uint32_t events) {
	const bool canRead = (events & (EPOLLIN | EPOLLERR | EPOLLHUP)) != 0;
	const bool canWrite = (events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) != 0;

	if (canRead) {
		while (true) {
			std::unique_ptr<AsyncRequest> req;
			{
				std::lock_guard lk(mMutex);
				if (state.readQueue.empty()) {
					break;
				}
				req = std::move(state.readQueue.front());
				state.readQueue.pop_front();
			}

			auto result = tryProcessPipeRead(*req);
			if (result.requeue) {
				std::lock_guard lk(mMutex);
				state.readQueue.emplace_front(std::move(req));
				updateRegistrationLocked(state);
				break;
			}
			if (result.completed) {
				completeRequest(*req, result.status, result.bytesTransferred);
			}
			{
				std::lock_guard lk(mMutex);
				updateRegistrationLocked(state);
			}
		}
	}

	if (canWrite) {
		while (true) {
			std::unique_ptr<AsyncRequest> req;
			{
				std::lock_guard lk(mMutex);
				if (state.writeQueue.empty()) {
					break;
				}
				req = std::move(state.writeQueue.front());
				state.writeQueue.pop_front();
			}

			auto result = tryProcessPipeWrite(*req);
			if (result.requeue) {
				std::lock_guard lk(mMutex);
				state.writeQueue.emplace_front(std::move(req));
				updateRegistrationLocked(state);
				break;
			}
			if (result.completed) {
				completeRequest(*req, result.status, result.bytesTransferred);
			}
			{
				std::lock_guard lk(mMutex);
				updateRegistrationLocked(state);
			}
		}
	}

	const int fd = state.fd;
	{
		std::lock_guard lk(mMutex);
		auto it = mFileStates.find(fd);
		if (it != mFileStates.end() && it->second.get() == &state) {
			FileState *ptr = it->second.get();
			if (!ptr->registered && ptr->readQueue.empty() && ptr->writeQueue.empty()) {
				restoreOriginalFlags(*ptr);
				mFileStates.erase(it);
			}
		}
	}
}

void EpollBackend::notifyWorker() const {
	if (mEventFd < 0) {
		return;
	}
	uint64_t value = 1;
	ssize_t rc;
	do {
		rc = write(mEventFd, &value, sizeof(value));
	} while (rc == -1 && errno == EINTR);
}

void EpollBackend::drainEventFd() const {
	uint64_t value;
	while (true) {
		ssize_t rc = read(mEventFd, &value, sizeof(value));
		if (rc == -1) {
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN) {
				break;
			}
		}
		if (rc == sizeof(value)) {
			continue;
		}
		break;
	}
}

void EpollBackend::updateRegistrationLocked(FileState &state) const {
	uint32_t desired = 0;
	if (!state.readQueue.empty()) {
		desired |= EPOLLIN;
	}
	if (!state.writeQueue.empty()) {
		desired |= EPOLLOUT;
	}

	if (desired == state.events && state.registered) {
		return;
	}

	if (desired == 0) {
		if (state.registered) {
			if (epoll_ctl(mEpollFd, EPOLL_CTL_DEL, state.fd, nullptr) != 0) {
				DEBUG_LOG("AsyncIO(epoll): epoll_ctl del fd %d failed: %d\n", state.fd, errno);
			}
			state.registered = false;
			state.events = 0;
		}
		restoreOriginalFlags(state);
		return;
	}

	struct epoll_event ev{};
	ev.events = desired;
	ev.data.ptr = &state;
	int op = state.registered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
	if (epoll_ctl(mEpollFd, op, state.fd, &ev) != 0) {
		DEBUG_LOG("AsyncIO(epoll): epoll_ctl op=%d fd=%d failed: %d\n", op, state.fd, errno);
		return;
	}
	state.registered = true;
	state.events = desired;
}

void EpollBackend::ensureNonBlocking(FileState &state) {
	if (state.originalFlags >= 0) {
		return;
	}

	int flags = fcntl(state.fd, F_GETFL, 0);
	if (flags < 0) {
		DEBUG_LOG("AsyncIO(epoll): fcntl(F_GETFL) failed for fd %d: %d\n", state.fd, errno);
		return;
	}

	if ((flags & O_NONBLOCK) != 0) {
		return;
	}

	state.originalFlags = flags;
	if (fcntl(state.fd, flags | O_NONBLOCK) != 0) {
		DEBUG_LOG("AsyncIO(epoll): fcntl(F_SETFL) failed for fd %d: %d\n", state.fd, errno);
		state.originalFlags = -1;
	}
}

void EpollBackend::restoreOriginalFlags(FileState &state) {
	if (state.originalFlags < 0) {
		return;
	}

	if (fcntl(state.fd, F_SETFL, state.originalFlags) != 0) {
		DEBUG_LOG("AsyncIO(epoll): restoring flags for fd %d failed: %d\n", state.fd, errno);
	}

	state.originalFlags = -1;
}

void EpollBackend::processCompletions() {
	std::deque<Completion> pending;
	{
		std::lock_guard lk(mCompletionMutex);
		if (mCompletions.empty()) {
			return;
		}
		pending.swap(mCompletions);
	}

	for (auto &entry : pending) {
		if (entry.req) {
			completeRequest(*entry.req, entry.status, entry.bytesTransferred);
		}
	}
}

void EpollBackend::failAllPending() {
	processCompletions();

	std::vector<std::unique_ptr<AsyncRequest>> pending;
	{
		std::lock_guard lk(mMutex);
		for (auto &entry : mFileStates) {
			auto &state = *entry.second;
			while (!state.readQueue.empty()) {
				pending.emplace_back(std::move(state.readQueue.front()));
				state.readQueue.pop_front();
			}
			while (!state.writeQueue.empty()) {
				pending.emplace_back(std::move(state.writeQueue.front()));
				state.writeQueue.pop_front();
			}
			state.registered = false;
			state.events = 0;
			restoreOriginalFlags(state);
		}
	}

	{
		std::lock_guard lk(mFileQueueMutex);
		while (!mFileQueue.empty()) {
			pending.emplace_back(std::move(mFileQueue.front()));
			mFileQueue.pop_front();
		}
	}

	std::deque<Completion> completions;
	{
		std::lock_guard lk(mCompletionMutex);
		completions.swap(mCompletions);
	}
	for (auto &entry : completions) {
		if (entry.req) {
			completeRequest(*entry.req, entry.status, entry.bytesTransferred);
		}
	}

	for (auto &req : pending) {
		if (req) {
			completeRequest(*req, kStatusCancelled, 0);
		}
	}
}

void EpollBackend::completeRequest(const AsyncRequest &req, NTSTATUS status, size_t bytesTransferred) {
	kernel32::detail::signalOverlappedEvent(req.file.get(), req.overlapped, status, bytesTransferred);
	mPending.fetch_sub(1, std::memory_order_acq_rel);
}

Completion EpollBackend::processBlockingRequest(AsyncRequest &req) {
	Completion result{};
	if (!req.file || !req.file->valid()) {
		result.status = STATUS_INVALID_HANDLE;
		return result;
	}

	files::IOResult io{};
	if (req.kind == AsyncRequest::Kind::Read) {
		io = files::read(req.file.get(), req.readBuffer, req.length, req.offset, req.updateFilePointer);
	} else {
		io = files::write(req.file.get(), req.writeBuffer, req.length, req.offset, req.updateFilePointer);
	}

	result.bytesTransferred = io.bytesTransferred;

	if (io.unixError != 0) {
		result.status = wibo::statusFromErrno(io.unixError);
		if (result.status == STATUS_SUCCESS) {
			result.status = STATUS_UNEXPECTED_IO_ERROR;
		}
	} else if (req.kind == AsyncRequest::Kind::Read && io.bytesTransferred == 0 && io.reachedEnd) {
		result.status = req.isPipe ? STATUS_PIPE_BROKEN : STATUS_END_OF_FILE;
	} else if (req.kind == AsyncRequest::Kind::Write && io.bytesTransferred == 0 && io.reachedEnd) {
		result.status = STATUS_END_OF_FILE;
	} else {
		result.status = STATUS_SUCCESS;
	}

	return result;
}

ProcessResult EpollBackend::tryProcessPipeRead(AsyncRequest &req) {
	ProcessResult result{};
	if (!req.file || !req.file->valid()) {
		result.completed = true;
		result.status = STATUS_INVALID_HANDLE;
		return result;
	}
	const int fd = req.file->fd;
	if (req.length == 0) {
		result.completed = true;
		result.status = STATUS_SUCCESS;
		return result;
	}

	uint8_t *buffer = static_cast<uint8_t *>(req.readBuffer);
	size_t toRead = req.length;
	while (true) {
		size_t chunk = std::min<size_t>(toRead, static_cast<size_t>(SSIZE_MAX));
		ssize_t rc = ::read(fd, buffer, chunk);
		if (rc > 0) {
			result.completed = true;
			result.status = STATUS_SUCCESS;
			result.bytesTransferred = static_cast<size_t>(rc);
			return result;
		}
		if (rc == 0) {
			result.completed = true;
			result.status = req.isPipe ? STATUS_PIPE_BROKEN : STATUS_END_OF_FILE;
			result.bytesTransferred = 0;
			return result;
		}
		if (rc == -1) {
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				result.requeue = true;
				return result;
			}
			int err = errno ? errno : EIO;
			result.completed = true;
			if (err == EPIPE || err == ECONNRESET) {
				result.status = STATUS_PIPE_BROKEN;
			} else {
				result.status = wibo::statusFromErrno(err);
				if (result.status == STATUS_SUCCESS) {
					result.status = STATUS_UNEXPECTED_IO_ERROR;
				}
			}
			result.bytesTransferred = 0;
			return result;
		}
	}
}

ProcessResult EpollBackend::tryProcessPipeWrite(AsyncRequest &req) {
	ProcessResult result{};
	if (!req.file || !req.file->valid()) {
		result.completed = true;
		result.status = STATUS_INVALID_HANDLE;
		return result;
	}

	const int fd = req.file->fd;
	size_t remaining = req.length - req.progress;
	const uint8_t *buffer = req.writeBuffer ? req.writeBuffer + req.progress : nullptr;

	while (remaining > 0) {
		size_t chunk = std::min<size_t>(remaining, static_cast<size_t>(SSIZE_MAX));
		ssize_t rc = ::write(fd, buffer, chunk);
		if (rc > 0) {
			size_t written = static_cast<size_t>(rc);
			req.progress += written;
			remaining -= written;
			buffer += written;
			if (req.offset.has_value()) {
				*req.offset += static_cast<off_t>(written);
			}
			continue;
		}
		if (rc == 0) {
			break;
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			result.requeue = true;
			return result;
		}
		int err = errno ? errno : EIO;
		result.completed = true;
		if (err == EPIPE || err == ECONNRESET) {
			result.status = STATUS_PIPE_BROKEN;
		} else {
			result.status = wibo::statusFromErrno(err);
			if (result.status == STATUS_SUCCESS) {
				result.status = STATUS_UNEXPECTED_IO_ERROR;
			}
		}
		result.bytesTransferred = req.progress;
		return result;
	}

	if (remaining == 0) {
		result.completed = true;
		result.status = STATUS_SUCCESS;
		result.bytesTransferred = req.progress;
	} else {
		result.requeue = true;
	}
	return result;
}

} // namespace

namespace wibo::detail {

std::unique_ptr<AsyncIOBackend> createEpollBackend() { return std::make_unique<EpollBackend>(); }

} // namespace wibo::detail
