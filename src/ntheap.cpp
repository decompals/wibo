// Windows NT heap model for HeapCreate'd heaps (WIBO_HEAP_MODEL=nt); see ntheap.h.
//
// Parameters are the documented NT defaults:
//  - HEAP_ENTRY is 8 bytes and the allocation granularity is 8 bytes on x86;
//  - FreeLists[1..127] hold free blocks of exactly that many 8-byte units, oldest first; FreeLists[0] holds the
//    larger ones sorted by size, a newly freed block going before blocks of equal size;
//  - an allocation takes the exact list, else the next non-empty dedicated list, else the first adequate entry of
//    FreeLists[0]; it uses the front of the block and returns a remainder of at least 16 bytes to the lists;
//  - when nothing fits, the first uncommitted range (segment order, then address order) that is large enough is
//    committed page by page; when no segment has room a new segment of SegmentReserve (1 MiB, the usual
//    SizeOfHeapReserve) is reserved bottom-up through VirtualAlloc;
//  - blocks larger than the VirtualMemoryThreshold (0x7f000 bytes) of a growable heap are VirtualAlloc'd with a
//    0x20-byte HEAP_VIRTUAL_ALLOC_ENTRY header;
//  - a free block of at least 0x1000 bytes is decommitted (whole pages) once the heap holds 0x10000 free bytes
//    (HeapDeCommitFreeBlockThreshold / HeapDeCommitTotalFreeThreshold).
// No front end (lookaside lists, LFH) is modelled; HEAP_NO_SERIALIZE heaps never get one on any NT version.

#include "ntheap.h"

#include "common.h"
#include "heap.h"

#include <cstdlib>
#include <cstring>
#include <iterator>

namespace wibo {

namespace {
constexpr uintptr_t kEntry = 8;
constexpr uintptr_t kPage = 0x1000;
constexpr uintptr_t kMinFree = 16;
constexpr uintptr_t kFirstSegmentOffset = 0x580; // HEAP + HEAP_SEGMENT + FreeLists in the first segment
constexpr uintptr_t kSegmentOffset = 0x40;		 // HEAP_SEGMENT in later segments
constexpr uintptr_t kVirtualThreshold = 0x7f000;
constexpr uintptr_t kVirtualHeader = 0x20;
constexpr uintptr_t kDecommitBlock = 0x1000;
constexpr uintptr_t kDecommitTotal = 0x10000;
constexpr uintptr_t kDefaultReserve = 0x100000;

inline uintptr_t pageUp(uintptr_t v) { return (v + kPage - 1) & ~(kPage - 1); }
inline uintptr_t pageDown(uintptr_t v) { return v & ~(kPage - 1); }

bool commitRange(uintptr_t addr, uintptr_t size) {
	void *base = reinterpret_cast<void *>(addr);
	std::size_t len = size;
	return heap::virtualAlloc(&base, &len, MEM_COMMIT, PAGE_READWRITE) == heap::VmStatus::Success;
}
} // namespace

bool ntHeapModelEnabled() {
	static const bool enabled = [] {
		const char *v = std::getenv("WIBO_HEAP_MODEL");
		return v && std::strcmp(v, "nt") == 0;
	}();
	return enabled;
}

NtHeap::NtHeap(DWORD flags, SIZE_T initialSize, SIZE_T maximumSize) {
	(void)flags;
	mGrowable = maximumSize == 0;
	mSegmentReserve = mGrowable ? kDefaultReserve : ((maximumSize + 0xffff) & ~uintptr_t(0xffff));
	if (mSegmentReserve < kDefaultReserve && mGrowable) {
		mSegmentReserve = kDefaultReserve;
	}
	if (newSegment(mSegmentReserve, kFirstSegmentOffset)) {
		uintptr_t want = pageUp(mSegments[0].base + (initialSize > kPage ? initialSize : kPage));
		Segment &s = mSegments[0];
		if (!s.uncommitted.empty() && want > s.uncommitted.begin()->first) {
			extend(want - s.uncommitted.begin()->first);
		}
	}
}

NtHeap::~NtHeap() {
	for (auto &u : mUsed) {
		if (u.second.virtualBlock) {
			heap::virtualFree(reinterpret_cast<void *>(u.second.block), 0, MEM_RELEASE);
		}
	}
	for (auto &s : mSegments) {
		heap::virtualFree(reinterpret_cast<void *>(s.base), 0, MEM_RELEASE);
	}
}

int NtHeap::segmentOf(uintptr_t addr) const {
	for (size_t i = 0; i < mSegments.size(); ++i) {
		if (addr >= mSegments[i].base && addr < mSegments[i].end) {
			return static_cast<int>(i);
		}
	}
	return -1;
}

bool NtHeap::newSegment(uintptr_t reserve, uintptr_t firstBlockOffset) {
	void *base = nullptr;
	std::size_t len = reserve;
	if (heap::virtualAlloc(&base, &len, MEM_RESERVE, PAGE_READWRITE) != heap::VmStatus::Success) {
		return false;
	}
	Segment s;
	s.base = reinterpret_cast<uintptr_t>(base);
	s.end = s.base + len;
	uintptr_t committed = pageUp(s.base + firstBlockOffset);
	if (!commitRange(s.base, committed - s.base)) {
		heap::virtualFree(base, 0, MEM_RELEASE);
		return false;
	}
	if (committed < s.end) {
		s.uncommitted[committed] = s.end;
	}
	mSegments.push_back(std::move(s));
	if (committed > mSegments.back().base + firstBlockOffset) {
		insertFree(mSegments.back().base + firstBlockOffset, committed - (mSegments.back().base + firstBlockOffset),
				   false, false);
	}
	DEBUG_LOG("NtHeap: segment %p..%p\n", base, reinterpret_cast<void *>(s.end));
	return true;
}

void NtHeap::removeFree(std::map<uintptr_t, FreeBlock>::iterator it) {
	mTotalFree -= it->second.size;
	mFree.erase(it);
}

void NtHeap::insertFree(uintptr_t addr, uintptr_t size, bool coalesce, bool mayDecommit) {
	if (coalesce) {
		int seg = segmentOf(addr);
		auto next = mFree.find(addr + size);
		if (next != mFree.end() && segmentOf(next->first) == seg) {
			size += next->second.size;
			removeFree(next);
		}
		auto prev = mFree.lower_bound(addr);
		if (prev != mFree.begin()) {
			--prev;
			if (prev->first + prev->second.size == addr && segmentOf(prev->first) == seg) {
				addr = prev->first;
				size += prev->second.size;
				removeFree(prev);
			}
		}
	}
	if (mayDecommit && size >= kDecommitBlock && mTotalFree + size >= kDecommitTotal) {
		uintptr_t end = addr + size;
		uintptr_t db = pageUp(addr), de = pageDown(end);
		if (db != addr && db - addr < kMinFree) {
			db += kPage;
		}
		if (de != end && end - de < kMinFree) {
			de -= kPage;
		}
		if (de > db) {
			int seg = segmentOf(addr);
			if (db > addr) {
				insertFree(addr, db - addr, false, false);
			}
			if (end > de) {
				insertFree(de, end - de, false, false);
			}
			heap::virtualFree(reinterpret_cast<void *>(db), de - db, MEM_DECOMMIT);
			auto &ucr = mSegments[seg].uncommitted;
			uintptr_t a = db, e = de;
			auto it = ucr.find(e);
			if (it != ucr.end()) {
				e = it->second;
				ucr.erase(it);
			}
			it = ucr.lower_bound(a);
			if (it != ucr.begin()) {
				auto p = std::prev(it);
				if (p->second == a) {
					a = p->first;
					ucr.erase(p);
				}
			}
			ucr[a] = e;
			return;
		}
	}
	mFree[addr] = FreeBlock{size, ++mSeq};
	mTotalFree += size;
}

bool NtHeap::extend(uintptr_t bytes) {
	uintptr_t need = pageUp(bytes);
	for (auto &s : mSegments) {
		for (auto it = s.uncommitted.begin(); it != s.uncommitted.end(); ++it) {
			if (it->second - it->first < need) {
				continue;
			}
			uintptr_t a = it->first, e = it->second;
			if (!commitRange(a, need)) {
				return false;
			}
			s.uncommitted.erase(it);
			if (a + need < e) {
				s.uncommitted[a + need] = e;
			}
			insertFree(a, need, true, false);
			return true;
		}
	}
	return false;
}

std::map<uintptr_t, NtHeap::FreeBlock>::iterator NtHeap::pick(uintptr_t bytes) {
	auto best = mFree.end();
	uintptr_t units = bytes / kEntry;
	if (units < 128) {
		for (auto it = mFree.begin(); it != mFree.end(); ++it) {
			uintptr_t u = it->second.size / kEntry;
			if (u < units || u >= 128) {
				continue;
			}
			if (best == mFree.end() || u < best->second.size / kEntry ||
				(u == best->second.size / kEntry && it->second.seq < best->second.seq)) {
				best = it;
			}
		}
		if (best != mFree.end()) {
			return best;
		}
	}
	for (auto it = mFree.begin(); it != mFree.end(); ++it) {
		if (it->second.size / kEntry < 128 || it->second.size < bytes) {
			continue;
		}
		if (best == mFree.end() || it->second.size < best->second.size ||
			(it->second.size == best->second.size && it->second.seq > best->second.seq)) {
			best = it;
		}
	}
	return best;
}

uintptr_t NtHeap::blockSize(SIZE_T request) const {
	uintptr_t s = ((static_cast<uintptr_t>(request) + kEntry - 1) & ~(kEntry - 1)) + kEntry;
	return s < kMinFree ? kMinFree : s;
}

void *NtHeap::alloc(SIZE_T request, bool zero) {
	std::lock_guard lk(mMutex);
	if (request == 0) {
		request = 1;
	}
	uintptr_t s = blockSize(request);
	if (mGrowable && s > kVirtualThreshold) {
		void *base = nullptr;
		std::size_t len = s - kEntry + kVirtualHeader;
		if (heap::virtualAlloc(&base, &len, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) != heap::VmStatus::Success) {
			return nullptr;
		}
		uintptr_t p = reinterpret_cast<uintptr_t>(base) + kVirtualHeader;
		mUsed[p] = UsedBlock{reinterpret_cast<uintptr_t>(base), len, request, true};
		return reinterpret_cast<void *>(p); // fresh pages are zero
	}
	auto it = pick(s);
	while (it == mFree.end()) {
		if (!extend(s)) {
			if (!mGrowable) {
				return nullptr;
			}
			uintptr_t reserve = mSegmentReserve;
			if (reserve < s + kSegmentOffset + kPage) {
				reserve = (s + kSegmentOffset + kPage + 0xffff) & ~uintptr_t(0xffff);
			}
			if (!newSegment(reserve, kSegmentOffset)) {
				return nullptr;
			}
		}
		it = pick(s);
	}
	uintptr_t a = it->first, fs = it->second.size;
	removeFree(it);
	if (fs - s >= kMinFree) {
		insertFree(a + s, fs - s, false, false);
	} else {
		s = fs;
	}
	uintptr_t p = a + kEntry;
	mUsed[p] = UsedBlock{a, s, request, false};
	if (zero) {
		std::memset(reinterpret_cast<void *>(p), 0, request);
	}
	return reinterpret_cast<void *>(p);
}

SIZE_T NtHeap::size(const void *ptr) const {
	std::lock_guard lk(mMutex);
	auto it = mUsed.find(reinterpret_cast<uintptr_t>(ptr));
	return it == mUsed.end() ? static_cast<SIZE_T>(-1) : it->second.request;
}

bool NtHeap::free(void *ptr) {
	std::lock_guard lk(mMutex);
	auto it = mUsed.find(reinterpret_cast<uintptr_t>(ptr));
	if (it == mUsed.end()) {
		return false;
	}
	UsedBlock b = it->second;
	mUsed.erase(it);
	if (b.virtualBlock) {
		heap::virtualFree(reinterpret_cast<void *>(b.block), 0, MEM_RELEASE);
		return true;
	}
	insertFree(b.block, b.size, true, true);
	return true;
}

void *NtHeap::realloc(void *ptr, SIZE_T request, bool zero, bool inPlaceOnly) {
	uintptr_t p = reinterpret_cast<uintptr_t>(ptr);
	SIZE_T oldRequest;
	{
		std::lock_guard lk(mMutex);
		auto it = mUsed.find(p);
		if (it == mUsed.end()) {
			return nullptr;
		}
		if (request == 0) {
			request = 1;
		}
		UsedBlock &b = it->second;
		oldRequest = b.request;
		uintptr_t s = blockSize(request);
		if (!b.virtualBlock && !(mGrowable && s > kVirtualThreshold)) {
			if (s <= b.size) { // shrink in place
				if (b.size - s >= kMinFree) {
					uintptr_t tail = b.block + s, tailSize = b.size - s;
					b.size = s;
					b.request = request;
					insertFree(tail, tailSize, true, true);
				} else {
					b.request = request;
				}
				if (zero && request > oldRequest) {
					std::memset(reinterpret_cast<void *>(p + oldRequest), 0, request - oldRequest);
				}
				return ptr;
			}
			auto next = mFree.find(b.block + b.size); // grow into the following free block
			if (next != mFree.end() && b.size + next->second.size >= s &&
				segmentOf(next->first) == segmentOf(b.block)) {
				uintptr_t total = b.size + next->second.size;
				removeFree(next);
				if (total - s >= kMinFree) {
					insertFree(b.block + s, total - s, false, false);
				} else {
					s = total;
				}
				b.size = s;
				b.request = request;
				if (zero) {
					std::memset(reinterpret_cast<void *>(p + oldRequest), 0, request - oldRequest);
				}
				return ptr;
			}
		} else if (b.virtualBlock && request <= b.size - kVirtualHeader) {
			b.request = request;
			return ptr;
		}
		if (inPlaceOnly) {
			return nullptr;
		}
	}
	void *q = alloc(request, zero);
	if (!q) {
		return nullptr;
	}
	std::memcpy(q, ptr, oldRequest < request ? oldRequest : request);
	free(ptr);
	return q;
}

} // namespace wibo
