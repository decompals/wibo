#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "test_assert.h"

// Heaps created by HeapCreate. The conformance checks hold for any heap; the layout checks describe the NT backend
// allocator modelled by WIBO_HEAP_MODEL=nt and run only when that variable is set.

#define NUM_BLOCKS 64

static int ntModelActive(void) {
	char value[8];
	DWORD len = GetEnvironmentVariableA("WIBO_HEAP_MODEL", value, sizeof(value));
	return len == 2 && strcmp(value, "nt") == 0;
}

static int g_ntModel;

// HeapSize reports the requested size on Windows and in the NT model; wibo's default heap may report more.
static void checkSize(HANDLE heap, const void *block, SIZE_T expected) {
	SIZE_T size = HeapSize(heap, 0, block);
	TEST_CHECK_MSG(size != (SIZE_T)-1 && size >= expected, "HeapSize %lu < %lu", (unsigned long)size,
				   (unsigned long)expected);
	if (g_ntModel) {
		TEST_CHECK_EQ(expected, size);
	}
}

static void fillPattern(uint8_t *p, SIZE_T size, uint8_t seed) {
	for (SIZE_T i = 0; i < size; i++) {
		p[i] = (uint8_t)(seed + i);
	}
}

static int checkPattern(const uint8_t *p, SIZE_T size, uint8_t seed) {
	for (SIZE_T i = 0; i < size; i++) {
		if (p[i] != (uint8_t)(seed + i)) {
			return 0;
		}
	}
	return 1;
}

static int isZero(const uint8_t *p, SIZE_T size) {
	for (SIZE_T i = 0; i < size; i++) {
		if (p[i] != 0) {
			return 0;
		}
	}
	return 1;
}

static void test_conformance(DWORD createFlags) {
	HANDLE heap = HeapCreate(createFlags, 0x1000, 0);
	TEST_CHECK(heap != NULL);

	uint8_t *blocks[NUM_BLOCKS];
	SIZE_T sizes[NUM_BLOCKS];
	for (int i = 0; i < NUM_BLOCKS; i++) {
		sizes[i] = 1 + (SIZE_T)i * 37 % 1500;
		blocks[i] = (uint8_t *)HeapAlloc(heap, i % 2 ? HEAP_ZERO_MEMORY : 0, sizes[i]);
		TEST_CHECK(blocks[i] != NULL);
		TEST_CHECK_EQ(0, (uintptr_t)blocks[i] % 8);
		checkSize(heap, blocks[i], sizes[i]);
		if (i % 2) {
			TEST_CHECK(isZero(blocks[i], sizes[i]));
		}
		fillPattern(blocks[i], sizes[i], (uint8_t)i);
	}
	for (int i = 0; i < NUM_BLOCKS; i++) {
		TEST_CHECK_MSG(checkPattern(blocks[i], sizes[i], (uint8_t)i), "block %d was overwritten", i);
		for (int j = i + 1; j < NUM_BLOCKS; j++) {
			int disjoint = blocks[i] + sizes[i] <= blocks[j] || blocks[j] + sizes[j] <= blocks[i];
			TEST_CHECK_MSG(disjoint, "blocks %d and %d overlap", i, j);
		}
	}

	// Free every other block and allocate again; the survivors keep their contents.
	for (int i = 0; i < NUM_BLOCKS; i += 2) {
		TEST_CHECK(HeapFree(heap, 0, blocks[i]));
	}
	for (int i = 0; i < NUM_BLOCKS; i += 2) {
		blocks[i] = (uint8_t *)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizes[i]);
		TEST_CHECK(blocks[i] != NULL);
		TEST_CHECK(isZero(blocks[i], sizes[i]));
		fillPattern(blocks[i], sizes[i], (uint8_t)(i + 100));
	}
	for (int i = 0; i < NUM_BLOCKS; i++) {
		TEST_CHECK(checkPattern(blocks[i], sizes[i], (uint8_t)(i % 2 ? i : i + 100)));
	}

	// Grow with HEAP_ZERO_MEMORY: old bytes kept, new bytes zeroed.
	uint8_t *grown = (uint8_t *)HeapReAlloc(heap, HEAP_ZERO_MEMORY, blocks[1], sizes[1] + 4000);
	TEST_CHECK(grown != NULL);
	TEST_CHECK(checkPattern(grown, sizes[1], 1));
	TEST_CHECK(isZero(grown + sizes[1], 4000));
	checkSize(heap, grown, sizes[1] + 4000);
	blocks[1] = grown;
	sizes[1] += 4000;

	// Shrinking in place always succeeds.
	uint8_t *shrunk = (uint8_t *)HeapReAlloc(heap, HEAP_REALLOC_IN_PLACE_ONLY, blocks[1], 10);
	TEST_CHECK(shrunk == blocks[1]);
	checkSize(heap, shrunk, 10);
	TEST_CHECK(checkPattern(shrunk, 10, 1));
	sizes[1] = 10;

	// A zero-byte allocation is a valid, distinct block.
	void *empty = HeapAlloc(heap, 0, 0);
	TEST_CHECK(empty != NULL);
	TEST_CHECK(empty != blocks[0]);
	TEST_CHECK(HeapFree(heap, 0, empty));

	// A block above the 0x7f000-byte VirtualMemoryThreshold of a growable heap.
	const SIZE_T bigSize = 0x100000;
	uint8_t *big = (uint8_t *)HeapAlloc(heap, HEAP_ZERO_MEMORY, bigSize);
	TEST_CHECK(big != NULL);
	TEST_CHECK_EQ(0, (uintptr_t)big % 8);
	checkSize(heap, big, bigSize);
	TEST_CHECK(big[0] == 0 && big[bigSize - 1] == 0);
	big[0] = 0x5a;
	big[bigSize - 1] = 0xa5;
	uint8_t *bigger = (uint8_t *)HeapReAlloc(heap, 0, big, bigSize * 2);
	TEST_CHECK(bigger != NULL);
	TEST_CHECK(bigger[0] == 0x5a && bigger[bigSize - 1] == 0xa5);
	TEST_CHECK(HeapFree(heap, 0, bigger));

	for (int i = 0; i < NUM_BLOCKS; i++) {
		TEST_CHECK(checkPattern(blocks[i], sizes[i], (uint8_t)(i % 2 ? i : i + 100)));
		TEST_CHECK(HeapFree(heap, 0, blocks[i]));
	}
	TEST_CHECK(HeapDestroy(heap));
}

// Block layout of the NT backend heap: 8-byte headers and granularity, carving from the front of the first segment,
// FIFO reuse of exact-size free lists, coalescing and in-place growth into a following free block.
static void test_nt_layout(void) {
	HANDLE heap = HeapCreate(HEAP_NO_SERIALIZE, 0x1000, 0);
	TEST_CHECK(heap != NULL);

	// The first block follows the 0x580-byte heap header and its own 8-byte header in a 64 KiB-aligned segment.
	uint8_t *a = (uint8_t *)HeapAlloc(heap, 0, 24);
	TEST_CHECK(a != NULL);
	TEST_CHECK_EQ(0x588, (uintptr_t)a & 0xffff);
	// Heaps sit low in the address space, as on Windows.
	TEST_CHECK_MSG((uintptr_t)a < 0x40000000, "heap block at %p", (void *)a);

	// Consecutive blocks are adjacent: request rounded up to 8 bytes plus an 8-byte header, at least 16 bytes.
	uint8_t *b = (uint8_t *)HeapAlloc(heap, 0, 24);
	uint8_t *c = (uint8_t *)HeapAlloc(heap, 0, 1);
	uint8_t *d = (uint8_t *)HeapAlloc(heap, 0, 24);
	uint8_t *e = (uint8_t *)HeapAlloc(heap, 0, 24);
	uint8_t *f = (uint8_t *)HeapAlloc(heap, 0, 24);
	TEST_CHECK(b == a + 32);
	TEST_CHECK(c == b + 32);
	TEST_CHECK(d == c + 16);
	TEST_CHECK(e == d + 32);
	TEST_CHECK(f == e + 32);

	// An exact-size free list is first in, first out.
	TEST_CHECK(HeapFree(heap, 0, d));
	TEST_CHECK(HeapFree(heap, 0, b));
	TEST_CHECK(HeapAlloc(heap, 0, 20) == d);
	TEST_CHECK(HeapAlloc(heap, 0, 24) == b);

	// Adjacent free blocks coalesce, and a larger free block is split at the front.
	TEST_CHECK(HeapFree(heap, 0, d));
	TEST_CHECK(HeapFree(heap, 0, e));
	uint8_t *de = (uint8_t *)HeapAlloc(heap, 0, 56);
	TEST_CHECK(de == d);
	TEST_CHECK(HeapFree(heap, 0, de));
	uint8_t *front = (uint8_t *)HeapAlloc(heap, 0, 8);
	TEST_CHECK(front == d);
	TEST_CHECK(HeapAlloc(heap, 0, 8) == d + 16);

	// Growth into the following free block happens in place.
	uint8_t *g = (uint8_t *)HeapAlloc(heap, 0, 64);
	uint8_t *h = (uint8_t *)HeapAlloc(heap, 0, 64);
	uint8_t *i = (uint8_t *)HeapAlloc(heap, 0, 64);
	TEST_CHECK(h == g + 72 && i == h + 72);
	TEST_CHECK(HeapFree(heap, 0, h));
	TEST_CHECK(HeapReAlloc(heap, HEAP_REALLOC_IN_PLACE_ONLY, g, 128) == g);
	TEST_CHECK(HeapReAlloc(heap, HEAP_REALLOC_IN_PLACE_ONLY, g, 256) == NULL);

	TEST_CHECK(HeapDestroy(heap));

	// A fixed-size heap cannot grow past its maximum.
	HANDLE fixed = HeapCreate(HEAP_NO_SERIALIZE, 0, 0x10000);
	TEST_CHECK(fixed != NULL);
	TEST_CHECK(HeapAlloc(fixed, 0, 0x8000) != NULL);
	TEST_CHECK(HeapAlloc(fixed, 0, 0x10000) == NULL);
	TEST_CHECK(HeapDestroy(fixed));
}

int main(void) {
	g_ntModel = ntModelActive();
	test_conformance(0);
	test_conformance(HEAP_NO_SERIALIZE);
	if (g_ntModel) {
		test_nt_layout();
	}
	return EXIT_SUCCESS;
}
