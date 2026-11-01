#include "test_assert.h"

#include <windows.h>

typedef PSLIST_ENTRY(WINAPI *PushFn)(PSLIST_HEADER, PSLIST_ENTRY);
typedef PSLIST_ENTRY(WINAPI *PopFn)(PSLIST_HEADER);
typedef VOID(WINAPI *InitFn)(PSLIST_HEADER);
typedef LONGLONG(WINAPI *CompareExchange64Fn)(LONGLONG volatile *, LONGLONG, LONGLONG);

typedef struct __attribute__((aligned(16))) {
	SLIST_ENTRY entry;
	int value;
} Item;

static SLIST_HEADER g_head __attribute__((aligned(16)));
static Item g_items[3];

int main(void) {
	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
	TEST_CHECK(kernel32 != NULL);
	InitFn init = (InitFn)(void *)GetProcAddress(kernel32, "InitializeSListHead");
	PushFn push = (PushFn)(void *)GetProcAddress(kernel32, "InterlockedPushEntrySList");
	PopFn pop = (PopFn)(void *)GetProcAddress(kernel32, "InterlockedPopEntrySList");
	CompareExchange64Fn cas64 = (CompareExchange64Fn)(void *)GetProcAddress(kernel32, "InterlockedCompareExchange64");
	TEST_CHECK(init && push && pop && cas64);

	init(&g_head);
	TEST_CHECK(pop(&g_head) == NULL);

	for (int i = 0; i < 3; ++i) {
		g_items[i].value = i;
	}
	TEST_CHECK(push(&g_head, &g_items[0].entry) == NULL);
	TEST_CHECK(push(&g_head, &g_items[1].entry) == &g_items[0].entry);
	TEST_CHECK(push(&g_head, &g_items[2].entry) == &g_items[1].entry);

	TEST_CHECK(pop(&g_head) == &g_items[2].entry);
	TEST_CHECK(pop(&g_head) == &g_items[1].entry);
	TEST_CHECK(pop(&g_head) == &g_items[0].entry);
	TEST_CHECK(pop(&g_head) == NULL);

	LONGLONG volatile value __attribute__((aligned(8))) = 0x1122334455667788LL;
	TEST_CHECK(cas64(&value, 5, 0x1LL) == 0x1122334455667788LL);
	TEST_CHECK(value == 0x1122334455667788LL);
	TEST_CHECK(cas64(&value, 0x0102030405060708LL, 0x1122334455667788LL) == 0x1122334455667788LL);
	TEST_CHECK(value == 0x0102030405060708LL);
	return 0;
}
