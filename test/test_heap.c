#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "test_assert.h"

const SIZE_T LARGE_BLOCK_SIZE = 64ULL * 1024ULL * 1024ULL; // 64 MiB
const SIZE_T SMALL_BLOCK_SIZE = 64ULL * 1024ULL;		   // 64 KiB

static void test_basics() {
	HANDLE processHeap = GetProcessHeap();
	TEST_CHECK(processHeap != NULL);

	uint8_t *block = (uint8_t *)HeapAlloc(processHeap, HEAP_ZERO_MEMORY, 32);
	TEST_CHECK(block != NULL);
	for (size_t i = 0; i < 32; i++) {
		TEST_CHECK(block[i] == 0);
	}

	SIZE_T blockSize = HeapSize(processHeap, 0, block);
	TEST_CHECK(blockSize >= 32);

	memset(block, 0xAA, 16);
	uint8_t *grown = (uint8_t *)HeapReAlloc(processHeap, HEAP_ZERO_MEMORY, block, 64);
	TEST_CHECK(grown != NULL);
	for (size_t i = 0; i < 16; i++) {
		TEST_CHECK(grown[i] == 0xAA);
	}
	for (size_t i = 16; i < 64; i++) {
		TEST_CHECK(grown[i] == 0);
	}

	SetLastError(0);
	void *inPlace = HeapReAlloc(processHeap, HEAP_REALLOC_IN_PLACE_ONLY, grown, 2048);
	TEST_CHECK(inPlace == NULL);
	TEST_CHECK_EQ(ERROR_NOT_ENOUGH_MEMORY, GetLastError());

	TEST_CHECK(HeapFree(processHeap, 0, grown));

	HANDLE privateHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
	TEST_CHECK(privateHeap != NULL);

	void *privateBlock = HeapAlloc(privateHeap, 0, 8);
	TEST_CHECK(privateBlock != NULL);

	SetLastError(0);
	// Disabled temporarily; no good way to detect individual heap allocations
	// in mimalloc currently. See https://github.com/microsoft/mimalloc/issues/298
#if 0
    TEST_CHECK(!HeapFree(processHeap, 0, privateBlock));
    TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());
#endif

	TEST_CHECK(HeapFree(privateHeap, 0, privateBlock));
	TEST_CHECK(HeapDestroy(privateHeap));

	SetLastError(0);
	TEST_CHECK(!HeapDestroy(processHeap));
	TEST_CHECK_EQ(ERROR_INVALID_HANDLE, GetLastError());
}

static void test_large_alloc() {
	HANDLE heap = HeapCreate(0, 0, 0);
	TEST_CHECK(heap != NULL);

	// Test allocating a large block
	void *largeBlock = HeapAlloc(heap, 0, LARGE_BLOCK_SIZE);
	*(uint32_t *)largeBlock = 0x12345678;
	TEST_CHECK(largeBlock != NULL);
	SIZE_T blockSize = HeapSize(heap, 0, largeBlock);
	TEST_CHECK(blockSize >= LARGE_BLOCK_SIZE);

	// Test reallocating a large block to a smaller size
	void *smallBlock = HeapReAlloc(heap, 0, largeBlock, SMALL_BLOCK_SIZE);
	TEST_CHECK(smallBlock != NULL);
	TEST_CHECK(*(uint32_t *)smallBlock == 0x12345678);
	blockSize = HeapSize(heap, 0, smallBlock);
	TEST_CHECK(blockSize >= SMALL_BLOCK_SIZE);

	// Test reallocating a small block to a larger size
	largeBlock = HeapReAlloc(heap, 0, smallBlock, LARGE_BLOCK_SIZE);
	TEST_CHECK(largeBlock != NULL);
	TEST_CHECK(*(uint32_t *)largeBlock == 0x12345678);
	TEST_CHECK(HeapFree(heap, 0, largeBlock));

	TEST_CHECK(HeapDestroy(heap));
}

static void test_heap_expansion() {
	HANDLE heap = HeapCreate(0, 0, 0);
	TEST_CHECK(heap != NULL);

	// Test allocating a total of 768 MiB
	const SIZE_T TOTAL_SIZE = 768ULL * 1024ULL * 1024ULL;
	for (int i = 0; i < (int)(TOTAL_SIZE / SMALL_BLOCK_SIZE); i++) {
		void *block = HeapAlloc(heap, 0, SMALL_BLOCK_SIZE);
		TEST_CHECK(block != NULL);
	}

	TEST_CHECK(HeapDestroy(heap));
}

int main(void) {
	test_basics();
	test_large_alloc();
	test_heap_expansion();
	return EXIT_SUCCESS;
}
