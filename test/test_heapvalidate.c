#include <windows.h>

#include "test_assert.h"

static void test_validate(HANDLE heap) {
	SetLastError(0x12345678);
	TEST_CHECK(HeapValidate(heap, 0, NULL));
	TEST_CHECK_EQ(0x12345678, GetLastError());

	const SIZE_T sizes[] = {0, 32, 64 * 1024 * 1024};
	for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
		void *block = HeapAlloc(heap, 0, sizes[i]);
		TEST_CHECK(block != NULL);
		SetLastError(0x12345678);
		TEST_CHECK(HeapValidate(heap, 0, block));
		TEST_CHECK_EQ(0x12345678, GetLastError());
		TEST_CHECK(HeapFree(heap, 0, block));
	}
}

int main(void) {
	test_validate(GetProcessHeap());

	HANDLE heap = HeapCreate(0, 0, 0);
	TEST_CHECK(heap != NULL);
	test_validate(heap);
	TEST_CHECK(HeapValidate(heap, HEAP_NO_SERIALIZE, NULL));
	TEST_CHECK(HeapDestroy(heap));
	return 0;
}
