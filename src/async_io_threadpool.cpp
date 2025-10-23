#include "async_io.h"

#include "errors.h"
#include "files.h"
#include "kernel32/overlapped_util.h"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

namespace {

struct AsyncRequest {
	enum class Kind { Read, Write };

	Kind kind;
	Pin<kernel32::FileObject> file;
	OVERLAPPED *overlapped = nullptr;
	void *buffer = nullptr;
	DWORD length = 0;
	std::optional<off_t> offset;
	bool isPipe = false;
	bool updateFilePointer = false;

	explicit AsyncRequest(Kind k) : kind(k) {}
};

class ThreadPoolBackend : public wibo::AsyncIOBackend {
  public:
	~ThreadPoolBackend() override { shutdown(); }

	bool init() override;
	void shutdown() override;
	[[nodiscard]] bool running() const noexcept override { return mActive.load(std::memory_order_acquire); }

	bool queueRead(Pin<kernel32::FileObject> file, OVERLAPPED *ov, void *buffer, DWORD length,
				   const std::optional<off_t> &offset, bool isPipe) override;
	bool queueWrite(Pin<kernel32::FileObject> file, OVERLAPPED *ov, const void *buffer, DWORD length,
					const std::optional<off_t> &offset, bool isPipe) override;

  private:
	bool enqueueRequest(std::unique_ptr<AsyncRequest> req);
	void workerLoop();
	static void processRequest(const AsyncRequest &req);

	std::atomic<bool> mActive{false};
	std::mutex mQueueMutex;
	std::condition_variable mQueueCv;
	std::deque<std::unique_ptr<AsyncRequest>> mQueue;
	std::vector<std::thread> mWorkers;
	std::atomic<uint32_t> mPending{0};
	bool mStopping = false; // guarded by mQueueMutex
};

bool ThreadPoolBackend::init() {
	bool expected = false;
	if (!mActive.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
		return true;
	}

	unsigned int threadCount = std::thread::hardware_concurrency();
	if (threadCount == 0) {
		threadCount = 1;
	}
	threadCount = std::min(threadCount, 4u); // cap to avoid oversubscription

	{
		std::lock_guard lk(mQueueMutex);
		mStopping = false;
	}
	mWorkers.reserve(threadCount);
	for (unsigned int i = 0; i < threadCount; ++i) {
		mWorkers.emplace_back(&ThreadPoolBackend::workerLoop, this);
	}
	DEBUG_LOG("thread pool backend initialized (workers=%u)\n", threadCount);
	return true;
}

void ThreadPoolBackend::shutdown() {
	if (!mActive.exchange(false, std::memory_order_acq_rel)) {
		return;
	}

	{
		std::lock_guard lk(mQueueMutex);
		mStopping = true;
	}
	mQueueCv.notify_all();

	for (auto &worker : mWorkers) {
		if (worker.joinable()) {
			worker.join();
		}
	}
	mWorkers.clear();

	{
		std::lock_guard lk(mQueueMutex);
		mQueue.clear();
		mStopping = false;
	}
	mPending.store(0, std::memory_order_release);
	DEBUG_LOG("thread-pool async backend shut down\n");
}

bool ThreadPoolBackend::queueRead(Pin<kernel32::FileObject> file, OVERLAPPED *ov, void *buffer, DWORD length,
								  const std::optional<off_t> &offset, bool isPipe) {
	auto req = std::make_unique<AsyncRequest>(AsyncRequest::Kind::Read);
	req->file = std::move(file);
	req->overlapped = ov;
	req->buffer = buffer;
	req->length = length;
	req->offset = offset;
	req->isPipe = isPipe;
	req->updateFilePointer = req->file ? !req->file->overlapped : true;
	return enqueueRequest(std::move(req));
}

bool ThreadPoolBackend::queueWrite(Pin<kernel32::FileObject> file, OVERLAPPED *ov, const void *buffer, DWORD length,
								   const std::optional<off_t> &offset, bool isPipe) {
	auto req = std::make_unique<AsyncRequest>(AsyncRequest::Kind::Write);
	req->file = std::move(file);
	req->overlapped = ov;
	req->buffer = const_cast<void *>(buffer);
	req->length = length;
	req->offset = offset;
	req->isPipe = isPipe;
	req->updateFilePointer = req->file ? !req->file->overlapped : true;
	return enqueueRequest(std::move(req));
}

bool ThreadPoolBackend::enqueueRequest(std::unique_ptr<AsyncRequest> req) {
	if (!running()) {
		return false;
	}
	if (!req || !req->file) {
		return false;
	}

	{
		std::lock_guard lk(mQueueMutex);
		if (mStopping) {
			return false;
		}
		mQueue.emplace_back(std::move(req));
		mPending.fetch_add(1, std::memory_order_acq_rel);
	}
	mQueueCv.notify_one();
	return true;
}

void ThreadPoolBackend::workerLoop() {
	while (true) {
		std::unique_ptr<AsyncRequest> req;
		{
			std::unique_lock lk(mQueueMutex);
			mQueueCv.wait(lk, [&] { return mStopping || !mQueue.empty(); });
			if (mStopping && mQueue.empty()) {
				break;
			}
			req = std::move(mQueue.front());
			mQueue.pop_front();
		}

		if (req) {
			processRequest(*req);
		}
		mPending.fetch_sub(1, std::memory_order_acq_rel);
	}
}

void ThreadPoolBackend::processRequest(const AsyncRequest &req) {
	if (!req.file || !req.file->valid()) {
		if (req.overlapped) {
			req.overlapped->Internal = STATUS_INVALID_HANDLE;
			req.overlapped->InternalHigh = 0;
			kernel32::detail::signalOverlappedEvent(req.overlapped);
		}
		return;
	}

	files::IOResult io{};
	if (req.kind == AsyncRequest::Kind::Read) {
		io = files::read(req.file.get(), req.buffer, req.length, req.offset, req.updateFilePointer);
	} else {
		const void *ptr = req.buffer;
		io = files::write(req.file.get(), ptr, req.length, req.offset, req.updateFilePointer);
	}

	NTSTATUS completionStatus = STATUS_SUCCESS;
	size_t bytesTransferred = io.bytesTransferred;

	if (io.unixError != 0) {
		completionStatus = wibo::statusFromErrno(io.unixError);
		if (completionStatus == STATUS_SUCCESS) {
			completionStatus = STATUS_UNEXPECTED_IO_ERROR;
		}
	} else if (req.kind == AsyncRequest::Kind::Read && bytesTransferred == 0 && io.reachedEnd) {
		completionStatus = req.isPipe ? STATUS_PIPE_BROKEN : STATUS_END_OF_FILE;
	} else if (req.kind == AsyncRequest::Kind::Write && bytesTransferred == 0 && io.reachedEnd) {
		completionStatus = STATUS_END_OF_FILE;
	}

	if (req.overlapped) {
		req.overlapped->Internal = completionStatus;
		req.overlapped->InternalHigh = bytesTransferred;
		kernel32::detail::signalOverlappedEvent(req.overlapped);
	}
}

} // namespace

namespace wibo::detail {

std::unique_ptr<AsyncIOBackend> createThreadPoolBackend() { return std::make_unique<ThreadPoolBackend>(); }

} // namespace wibo::detail
