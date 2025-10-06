#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "test_assert.h"

int main(void) {
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
    TEST_CHECK(!HeapFree(processHeap, 0, privateBlock));
    TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());

    TEST_CHECK(HeapFree(privateHeap, 0, privateBlock));
    TEST_CHECK(HeapDestroy(privateHeap));

    SetLastError(0);
    TEST_CHECK(!HeapDestroy(processHeap));
    TEST_CHECK_EQ(ERROR_INVALID_HANDLE, GetLastError());

    return EXIT_SUCCESS;
}
