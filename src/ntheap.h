#pragma once

// Optional model of the Windows NT heap for HeapCreate'd heaps, enabled with WIBO_HEAP_MODEL=nt.
//
// Some programs' output depends on the addresses their heap returns (e.g. Intel C/C++ 4.0's mcpcom orders the
// operands of commutative expressions by the addresses of its symbol records), so it differs between wibo's
// mimalloc arenas and a real Windows heap. In this mode, heaps created by HeapCreate behave like the NT backend
// allocator (RtlAllocateHeap without a front end): 8-byte block headers and granularity, dedicated free lists for
// blocks under 1 KiB plus a size-ordered list, splitting at the front, coalescing on free, segments reserved
// bottom-up through VirtualAlloc and committed page by page, decommit of large free blocks, and blocks over the
// VirtualMemoryThreshold allocated directly. The process heap keeps wibo's default allocator.

#include "types.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace wibo {

bool ntHeapModelEnabled();

class NtHeap {
  public:
	NtHeap(DWORD flags, SIZE_T initialSize, SIZE_T maximumSize);
	~NtHeap();
	NtHeap(const NtHeap &) = delete;
	NtHeap &operator=(const NtHeap &) = delete;

	void *alloc(SIZE_T size, bool zero);
	void *realloc(void *ptr, SIZE_T size, bool zero, bool inPlaceOnly);
	bool free(void *ptr);
	SIZE_T size(const void *ptr) const;

  private:
	struct FreeBlock {
		uintptr_t size;
		uint64_t seq;
	};
	struct UsedBlock {
		uintptr_t block;   // address of the HEAP_ENTRY (or of the VirtualAlloc'd region)
		uintptr_t size;	   // block size in bytes including the header (region size for VirtualAlloc'd blocks)
		SIZE_T request;	   // caller's size, returned by HeapSize
		bool virtualBlock; // VirtualAlloc'd (over the threshold)
	};
	struct Segment {
		uintptr_t base, end;
		std::map<uintptr_t, uintptr_t> uncommitted; // start -> end
	};

	bool newSegment(uintptr_t reserve, uintptr_t firstBlockOffset);
	bool extend(uintptr_t bytes);
	void insertFree(uintptr_t addr, uintptr_t size, bool coalesce, bool mayDecommit);
	void removeFree(std::map<uintptr_t, FreeBlock>::iterator it);
	int segmentOf(uintptr_t addr) const;
	std::map<uintptr_t, FreeBlock>::iterator pick(uintptr_t bytes);
	uintptr_t blockSize(SIZE_T request) const;

	mutable std::mutex mMutex;
	bool mGrowable;
	uintptr_t mSegmentReserve;
	std::vector<Segment> mSegments;
	std::map<uintptr_t, FreeBlock> mFree;			// block address -> free block
	std::unordered_map<uintptr_t, UsedBlock> mUsed; // user pointer -> block
	uintptr_t mTotalFree = 0;
	uint64_t mSeq = 0;
};

} // namespace wibo
