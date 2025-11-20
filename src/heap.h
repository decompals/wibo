#pragma once

#include "types.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <vector>

struct mi_heap_s;
typedef struct mi_heap_s mi_heap_t;

namespace wibo {

namespace detail {

struct HeapInternal {
	uint32_t heapTag;
	// Previously used arena
	uint32_t arenaHint = 0;
	// Thread-local mi_heap objects per arena
	std::vector<mi_heap_t *> heaps;

	explicit HeapInternal(uint32_t heapTag) : heapTag(heapTag) {}
	~HeapInternal() = default;
};

}; // namespace detail

class Heap {
  public:
	Heap();
	~Heap();

	Heap(const Heap &) = delete;
	Heap &operator=(const Heap &) = delete;
	Heap(Heap &&) noexcept = default;
	Heap &operator=(Heap &&) noexcept = default;

	void *malloc(size_t size, bool zero = false);
	void *realloc(void *ptr, size_t newSize, bool zero = false);
	bool free(void *ptr);

  private:
	uint32_t threadId;
	detail::HeapInternal internal;
};

}; // namespace wibo

namespace wibo::heap {

uintptr_t systemPageSize();
uintptr_t allocationGranularity();

enum class VmStatus : uint32_t {
	Success = 0,
	InvalidParameter,
	InvalidAddress,
	NoAccess,
	NotSupported,
	NoMemory,
	Rejected,
	UnknownError,
};

// Guest heap memory allocation helpers
void *guestMalloc(std::size_t size, bool zero = false);
void *guestRealloc(void *ptr, std::size_t newSize, bool zero = false);
bool guestFree(void *ptr);
size_t guestSize(const void *ptr);

VmStatus virtualAlloc(void **baseAddress, std::size_t *regionSize, DWORD allocationType, DWORD protect,
					  DWORD type = MEM_PRIVATE);
VmStatus virtualFree(void *baseAddress, std::size_t regionSize, DWORD freeType);
VmStatus virtualProtect(void *baseAddress, std::size_t regionSize, DWORD newProtect, DWORD *oldProtect);
VmStatus virtualQuery(const void *address, MEMORY_BASIC_INFORMATION *outInfo);
VmStatus virtualReset(void *baseAddress, std::size_t regionSize);

VmStatus reserveViewRange(std::size_t regionSize, uintptr_t minAddr, uintptr_t maxAddr, void **baseAddress);
void registerViewRange(void *baseAddress, std::size_t regionSize, DWORD allocationProtect, DWORD protect);
void releaseViewRange(void *baseAddress);

DWORD win32ErrorFromVmStatus(VmStatus status);
NTSTATUS ntStatusFromVmStatus(VmStatus status);

bool reserveGuestStack(std::size_t stackSizeBytes, void **outStackLimit, void **outStackBase);

//-------------------- deleters --------------------
template <class U> struct single_deleter {
	void operator()(U *p) const noexcept {
		if (!p)
			return;
		p->~U();
		wibo::heap::guestFree(static_cast<void *>(p));
	}
};

template <class U> struct array_deleter {
	std::size_t n{}; // number of elements
	void operator()(U *p) const noexcept {
		if (!p)
			return;
		for (std::size_t i = n; i > 0; --i)
			(p + (i - 1))->~U();
		wibo::heap::guestFree(static_cast<void *>(p));
	}
};

//-------------------- pointer alias picking T or T[] --------------------
template <class T> struct unique_type {
	using type = std::unique_ptr<T, single_deleter<T>>;
};
template <class T> struct unique_type<T[]> {
	using type = std::unique_ptr<T[], array_deleter<T>>;
};
// template <class T, std::size_t> struct unique_type<T[]>; // no bounded arrays (int[N])

template <class T> using guest_ptr = typename unique_type<T>::type;

//-------------------- helpers --------------------
inline bool mul_overflows(std::size_t a, std::size_t b) {
	return b != 0 && a > (std::numeric_limits<std::size_t>::max)() / b;
}

//-------------------- single object --------------------
template <class T, class... Args>
	requires(!std::is_array_v<T>)
guest_ptr<T> make_guest_unique(Args &&...args) noexcept {
	// Optional: insist on nothrow construction in a no-exception build
	static_assert(std::is_nothrow_constructible_v<T, Args...>,
				  "T must be nothrow-constructible when exceptions are disabled");

	void *raw = wibo::heap::guestMalloc(sizeof(T));
	if (!raw)
		return {};

	// placement-new without exceptions
	T *p = ::new (raw) T(std::forward<Args>(args)...);
	return guest_ptr<T>(p, single_deleter<T>{});
}

//-------------------- unbounded array: default-construct --------------------
template <class T>
	requires std::is_unbounded_array_v<T>
guest_ptr<T> make_guest_unique(std::size_t n) noexcept {
	using U = std::remove_extent_t<T>;
	static_assert(std::is_nothrow_default_constructible_v<U>,
				  "U must be nothrow default-constructible when exceptions are disabled");

	if (mul_overflows(n, sizeof(U)))
		return {};
	void *raw = wibo::heap::guestMalloc(n * sizeof(U));
	if (!raw)
		return {};
	U *p = static_cast<U *>(raw);

	for (std::size_t i = 0; i < n; ++i)
		::new (p + i) U();

	return guest_ptr<T>(p, array_deleter<U>{n});
}

//-------------------- unbounded array: per-element args --------------------
template <class T, class... Args>
	requires std::is_unbounded_array_v<T>
guest_ptr<T> make_guest_unique(std::size_t n, Args &&...args) noexcept {
	using U = std::remove_extent_t<T>;
	static_assert(std::is_nothrow_constructible_v<U, Args...>,
				  "U(args...) must be nothrow-constructible when exceptions are disabled");

	if (mul_overflows(n, sizeof(U)))
		return {};
	void *raw = wibo::heap::guestMalloc(n * sizeof(U));
	if (!raw)
		return {};
	U *p = static_cast<U *>(raw);

	for (std::size_t i = 0; i < n; ++i)
		::new (p + i) U(std::forward<Args>(args)...);

	return guest_ptr<T>(p, array_deleter<U>{n});
}

} // namespace wibo::heap
