#include "async_io.h"

#include "errors.h"
#include "kernel32/internal.h"
#include "kernel32/overlapped_util.h"

#include <liburing.h>
#include <optional>

namespace {

constexpr unsigned kQueueDepth = 64;

struct AsyncRequest {
	enum class Kind { Read, Write, Shutdown };

	Kind kind;
	Pin<kernel32::FileObject> file;
	OVERLAPPED *overlapped = nullptr;
	bool isPipe = false;
	struct iovec vec{};
};

class IoUringBackend : public wibo::AsyncIOBackend {
  public:
	~IoUringBackend() override { shutdown(); }
	bool init() override;
	void shutdown() override;
	[[nodiscard]] bool running() const noexcept override { return mRunning.load(std::memory_order_acquire); }

	bool queueRead(Pin<kernel32::FileObject> file, OVERLAPPED *ov, void *buffer, DWORD length,
				   const std::optional<off_t> &offset, bool isPipe) override;
	bool queueWrite(Pin<kernel32::FileObject> file, OVERLAPPED *ov, const void *buffer, DWORD length,
					const std::optional<off_t> &offset, bool isPipe) override;

  private:
	bool enqueueRequest(AsyncRequest *req, void *buffer, DWORD length, const std::optional<off_t> &offset,
						bool isWrite);
	void requestStop();
	void workerLoop();
	void handleCompletion(struct io_uring_cqe *cqe);
	void notifySpace();

	struct io_uring mRing{};
	std::mutex mSubmitMutex;
	std::condition_variable mQueueCv;
	std::atomic<bool> mRunning{false};
	std::atomic<uint32_t> mPending{0};
	std::thread mThread;
};

bool IoUringBackend::init() {
	if (mRunning.load(std::memory_order_acquire)) {
		return true;
	}
	int rc = io_uring_queue_init(kQueueDepth, &mRing, 0);
	if (rc < 0) {
		DEBUG_LOG("io_uring_queue_init failed: %d\n", rc);
		return false;
	}
	mRunning.store(true, std::memory_order_release);
	mThread = std::thread(&IoUringBackend::workerLoop, this);
	DEBUG_LOG("io_uring backend initialized (depth=%u)\n", kQueueDepth);
	return true;
}

void IoUringBackend::shutdown() {
	if (!mRunning.exchange(false, std::memory_order_acq_rel)) {
		return;
	}
	requestStop();
	if (mThread.joinable()) {
		mThread.join();
	}
	io_uring_queue_exit(&mRing);
}

bool IoUringBackend::queueRead(Pin<kernel32::FileObject> file, OVERLAPPED *ov, void *buffer, DWORD length,
							   const std::optional<off_t> &offset, bool isPipe) {
	auto *req = new AsyncRequest{AsyncRequest::Kind::Read, std::move(file), ov, isPipe};
	if (!enqueueRequest(req, buffer, length, offset, false)) {
		delete req;
		return false;
	}
	return true;
}

bool IoUringBackend::queueWrite(Pin<kernel32::FileObject> file, OVERLAPPED *ov, const void *buffer, DWORD length,
								const std::optional<off_t> &offset, bool isPipe) {
	auto *req = new AsyncRequest{AsyncRequest::Kind::Write, std::move(file), ov, isPipe};
	if (!enqueueRequest(req, const_cast<void *>(buffer), length, offset, true)) {
		delete req;
		return false;
	}
	return true;
}

bool IoUringBackend::enqueueRequest(AsyncRequest *req, void *buffer, DWORD length, const std::optional<off_t> &offset,
									bool isWrite) {
	std::unique_lock lock(mSubmitMutex);
	if (!mRunning.load(std::memory_order_acquire) && req->kind != AsyncRequest::Kind::Shutdown) {
		return false;
	}

	struct io_uring_sqe *sqe;
	while (true) {
		sqe = io_uring_get_sqe(&mRing);
		if (!sqe) {
			mQueueCv.wait(lock);
			if (!mRunning.load(std::memory_order_acquire) && req->kind != AsyncRequest::Kind::Shutdown) {
				return false;
			}
			continue;
		}
		io_uring_sqe_set_data(sqe, req);
		if (req->kind == AsyncRequest::Kind::Shutdown) {
			io_uring_prep_nop(sqe);
		} else {
			req->vec.iov_base = buffer;
			req->vec.iov_len = length;
			off_t fileOffset = -1;
			if (!req->isPipe && offset.has_value()) {
				fileOffset = *offset;
			}
			int fd = req->file ? req->file->fd : -1;
			if (isWrite) {
				io_uring_prep_writev(sqe, fd, &req->vec, 1, fileOffset);
			} else {
				io_uring_prep_readv(sqe, fd, &req->vec, 1, fileOffset);
			}
		}
		mPending.fetch_add(1, std::memory_order_relaxed);
		break;
	}

	while (true) {
		int res = io_uring_submit(&mRing);
		if (res >= 0) {
			break;
		} else if (res == -EINTR) {
			continue;
		} else if (res == -EBUSY || res == -EAGAIN) {
			lock.unlock();
			std::this_thread::yield();
			lock.lock();
			continue;
		}
		DEBUG_LOG("io_uring_submit failed (will retry): %d\n", res);
	}

	lock.unlock();
	mQueueCv.notify_one();
	return true;
}

void IoUringBackend::requestStop() {
	mRunning.store(false, std::memory_order_release);
	auto *req = new AsyncRequest{AsyncRequest::Kind::Shutdown, Pin<kernel32::FileObject>{}, nullptr, false};
	if (!enqueueRequest(req, nullptr, 0, std::nullopt, false)) {
		delete req;
	}
}

void IoUringBackend::workerLoop() {
	while (mRunning.load(std::memory_order_acquire) || mPending.load(std::memory_order_acquire) > 0) {
		struct io_uring_cqe *cqe = nullptr;
		int ret = io_uring_wait_cqe(&mRing, &cqe);
		if (ret == -EINTR) {
			continue;
		}
		if (ret < 0) {
			DEBUG_LOG("io_uring_wait_cqe failed: %d\n", ret);
			continue;
		}
		handleCompletion(cqe);
		io_uring_cqe_seen(&mRing, cqe);
		notifySpace();
	}

	while (mPending.load(std::memory_order_acquire) > 0) {
		struct io_uring_cqe *cqe = nullptr;
		int ret = io_uring_peek_cqe(&mRing, &cqe);
		if (ret != 0 || !cqe) {
			break;
		}
		handleCompletion(cqe);
		io_uring_cqe_seen(&mRing, cqe);
		notifySpace();
	}
}

void IoUringBackend::handleCompletion(struct io_uring_cqe *cqe) {
	auto *req = static_cast<AsyncRequest *>(io_uring_cqe_get_data(cqe));
	if (!req) {
		return;
	}

	if (req->kind == AsyncRequest::Kind::Shutdown) {
		delete req;
		mPending.fetch_sub(1, std::memory_order_acq_rel);
		return;
	}

	OVERLAPPED *ov = req->overlapped;
	if (ov) {
		if (cqe->res >= 0) {
			ov->InternalHigh = static_cast<ULONG_PTR>(cqe->res);
			if (req->kind == AsyncRequest::Kind::Read && cqe->res == 0) {
				ov->Internal = req->isPipe ? STATUS_PIPE_BROKEN : STATUS_END_OF_FILE;
			} else {
				ov->Internal = STATUS_SUCCESS;
			}
		} else {
			int err = -cqe->res;
			ov->InternalHigh = 0;
			if (err == EPIPE) {
				ov->Internal = STATUS_PIPE_BROKEN;
			} else {
				NTSTATUS status = wibo::statusFromErrno(err);
				if (status == STATUS_SUCCESS) {
					status = STATUS_UNEXPECTED_IO_ERROR;
				}
				ov->Internal = status;
			}
		}
		kernel32::detail::signalOverlappedEvent(ov);
	}

	delete req;
	mPending.fetch_sub(1, std::memory_order_acq_rel);
}

void IoUringBackend::notifySpace() {
	std::lock_guard lk(mSubmitMutex);
	mQueueCv.notify_all();
}

} // namespace

namespace wibo::detail {

std::unique_ptr<AsyncIOBackend> createIoUringBackend() { return std::make_unique<IoUringBackend>(); }

} // namespace wibo::detail
