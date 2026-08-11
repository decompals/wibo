#include "guest_stubs.h"

#include "heap.h"
#include "winnls.h"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <new>
#include <pthread.h>
#include <sys/time.h>
#include <thread>
#include <time.h>

namespace {

constexpr size_t kGetLastErrorOffset = 0;
constexpr size_t kSetLastErrorOffset = 16;
constexpr size_t kGetCurrentThreadIdOffset = 32;
constexpr size_t kIsDBCSLeadByteOffset = 48;
constexpr size_t kGetTickCountOffset = 64;

constexpr std::array<uint8_t, 7> kGetLastErrorStub = {
	0x64, 0xA1, 0x34, 0x00, 0x00, 0x00, // mov eax, fs:[0x34]
	0xC3,								// ret
};
constexpr std::array<uint8_t, 14> kSetLastErrorStub = {
	0x8B, 0x4C, 0x24, 0x04,					  // mov ecx, [esp+4]
	0x64, 0x89, 0x0D, 0x34, 0x00, 0x00, 0x00, // mov fs:[0x34], ecx
	0xC2, 0x04, 0x00,						  // ret 4
};
constexpr std::array<uint8_t, 7> kGetCurrentThreadIdStub = {
	0x64, 0xA1, 0x24, 0x00, 0x00, 0x00, // mov eax, fs:[0x24]
	0xC3,								// ret
};
constexpr std::array<uint8_t, 5> kIsDBCSLeadByteStub = {
	0x31, 0xC0,		  // xor eax, eax
	0xC2, 0x04, 0x00, // ret 4
};
constexpr std::array<uint8_t, 6> kGetTickCountStub = {
	0xA1, 0x00, 0x00, 0x00, 0x00, // mov eax, ds:[tickAddress]
	0xC3,						  // ret
};

static_assert(sizeof(std::atomic<DWORD>) == sizeof(DWORD));
static_assert(alignof(std::atomic<DWORD>) == alignof(DWORD));
static_assert(std::atomic<DWORD>::is_always_lock_free);

struct GuestStubState {
	std::mutex mutex;
	uint8_t *codePage = nullptr;
	std::atomic<DWORD> *tick = nullptr;
	bool initialized = false;
	bool initializationFailed = false;
	bool tickUpdaterStarted = false;
};

GuestStubState &guestStubState() {
	// The detached updater and its pages live until process exit, when the OS reclaims them.
	static GuestStubState *state = new GuestStubState;
	return *state;
}

template <size_t Size> void copyStub(uint8_t *codePage, size_t offset, const std::array<uint8_t, Size> &stub) {
	std::memcpy(codePage + offset, stub.data(), stub.size());
}

bool isDbcsCodePage(UINT codePage) {
	switch (codePage) {
	case 932:
	case 936:
	case 949:
	case 950:
	case 1361:
		return true;
	default:
		return false;
	}
}

bool initializeGuestStubsLocked(GuestStubState &state) {
	if (state.initialized) {
		return true;
	}
	if (state.initializationFailed) {
		return false;
	}

	size_t codePageSize = wibo::heap::systemPageSize();
	void *codePage = nullptr;
	if (wibo::heap::virtualAlloc(&codePage, &codePageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) !=
		wibo::heap::VmStatus::Success) {
		state.initializationFailed = true;
		return false;
	}

	size_t tickPageSize = wibo::heap::systemPageSize();
	void *tickPage = nullptr;
	if (wibo::heap::virtualAlloc(&tickPage, &tickPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) !=
		wibo::heap::VmStatus::Success) {
		wibo::heap::virtualFree(codePage, 0, MEM_RELEASE);
		state.initializationFailed = true;
		return false;
	}

	auto *code = static_cast<uint8_t *>(codePage);
	auto *tick = ::new (tickPage) std::atomic<DWORD>(wibo::guestStubs::queryTickCount());
	copyStub(code, kGetLastErrorOffset, kGetLastErrorStub);
	copyStub(code, kSetLastErrorOffset, kSetLastErrorStub);
	copyStub(code, kGetCurrentThreadIdOffset, kGetCurrentThreadIdStub);
	copyStub(code, kIsDBCSLeadByteOffset, kIsDBCSLeadByteStub);
	copyStub(code, kGetTickCountOffset, kGetTickCountStub);

	GUEST_PTR tickAddress = toGuestPtr(tickPage);
	std::memcpy(code + kGetTickCountOffset + 1, &tickAddress, sizeof(tickAddress));
	__builtin___clear_cache(reinterpret_cast<char *>(code),
							reinterpret_cast<char *>(code + kGetTickCountOffset + kGetTickCountStub.size()));

	if (wibo::heap::virtualProtect(codePage, codePageSize, PAGE_EXECUTE_READ, nullptr) !=
		wibo::heap::VmStatus::Success) {
		wibo::heap::virtualFree(tickPage, 0, MEM_RELEASE);
		wibo::heap::virtualFree(codePage, 0, MEM_RELEASE);
		state.initializationFailed = true;
		return false;
	}

	state.codePage = code;
	state.tick = tick;
	state.initialized = true;
	return true;
}

void *tickUpdater(void *opaque) {
	auto *state = static_cast<GuestStubState *>(opaque);
	auto nextUpdate = std::chrono::steady_clock::now();
	for (;;) {
		state->tick->store(wibo::guestStubs::queryTickCount(), std::memory_order_relaxed);
		nextUpdate += std::chrono::milliseconds(1);
		auto now = std::chrono::steady_clock::now();
		if (nextUpdate <= now) {
			nextUpdate = now + std::chrono::milliseconds(1);
		}
		std::this_thread::sleep_until(nextUpdate);
	}
}

bool startTickUpdaterLocked(GuestStubState &state) {
	if (state.tickUpdaterStarted) {
		return true;
	}

	state.tick->store(wibo::guestStubs::queryTickCount(), std::memory_order_relaxed);
	pthread_attr_t attr;
	if (pthread_attr_init(&attr) != 0) {
		return false;
	}
	if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0) {
		pthread_attr_destroy(&attr);
		return false;
	}
	pthread_t thread;
	int result = pthread_create(&thread, &attr, tickUpdater, &state);
	pthread_attr_destroy(&attr);
	if (result != 0) {
		return false;
	}

	state.tickUpdaterStarted = true;
	return true;
}

} // namespace

namespace wibo::guestStubs {

DWORD queryTickCount() {
#if defined(CLOCK_MONOTONIC)
	struct timespec ts{};
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
		uint64_t milliseconds =
			static_cast<uint64_t>(ts.tv_sec) * 1000ULL + static_cast<uint64_t>(ts.tv_nsec) / 1000000ULL;
		return static_cast<DWORD>(milliseconds & 0xFFFFFFFFULL);
	}
#endif
	struct timeval tv{};
	if (gettimeofday(&tv, nullptr) == 0) {
		uint64_t milliseconds =
			static_cast<uint64_t>(tv.tv_sec) * 1000ULL + static_cast<uint64_t>(tv.tv_usec) / 1000ULL;
		return static_cast<DWORD>(milliseconds & 0xFFFFFFFFULL);
	}
	return 0;
}

void *resolveByName(const char *name) {
	if (!name) {
		return nullptr;
	}

	size_t offset;
	bool needsTickUpdater = false;
	if (std::strcmp(name, "GetLastError") == 0) {
		offset = kGetLastErrorOffset;
	} else if (std::strcmp(name, "SetLastError") == 0) {
		offset = kSetLastErrorOffset;
	} else if (std::strcmp(name, "GetCurrentThreadId") == 0) {
		offset = kGetCurrentThreadIdOffset;
	} else if (std::strcmp(name, "IsDBCSLeadByte") == 0) {
		if (isDbcsCodePage(kernel32::GetACP())) {
			return nullptr;
		}
		offset = kIsDBCSLeadByteOffset;
	} else if (std::strcmp(name, "GetTickCount") == 0) {
		offset = kGetTickCountOffset;
		needsTickUpdater = true;
	} else {
		return nullptr;
	}

	auto &state = guestStubState();
	std::lock_guard lock(state.mutex);
	if (!initializeGuestStubsLocked(state)) {
		return nullptr;
	}
	if (needsTickUpdater && !startTickUpdaterLocked(state)) {
		return nullptr;
	}
	return state.codePage + offset;
}

} // namespace wibo::guestStubs
