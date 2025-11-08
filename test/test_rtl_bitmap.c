#include <windows.h>
#include <string.h>

#include "test_assert.h"

typedef struct _TEST_RTL_BITMAP {
    ULONG SizeOfBitMap;
    PULONG Buffer;
} TEST_RTL_BITMAP;

typedef VOID(WINAPI *RtlInitializeBitMapFn)(TEST_RTL_BITMAP *, PULONG, ULONG);
typedef VOID(WINAPI *RtlSetBitsFn)(TEST_RTL_BITMAP *, ULONG, ULONG);
typedef BOOLEAN(WINAPI *RtlAreBitsSetFn)(TEST_RTL_BITMAP *, ULONG, ULONG);
typedef BOOLEAN(WINAPI *RtlAreBitsClearFn)(TEST_RTL_BITMAP *, ULONG, ULONG);

static struct {
    RtlInitializeBitMapFn initialize;
    RtlSetBitsFn set_bits;
    RtlAreBitsSetFn are_bits_set;
    RtlAreBitsClearFn are_bits_clear;
} gRtlBitmapFns;

static FARPROC load_ntdll_proc(const char *name) {
    static HMODULE ntdll;
    if (!ntdll) {
        ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) {
            ntdll = LoadLibraryW(L"ntdll.dll");
        }
    }
    TEST_CHECK(ntdll != NULL);
    FARPROC proc = GetProcAddress(ntdll, name);
    TEST_CHECK(proc != NULL);
    return proc;
}

static void load_rtl_bitmap_functions(void) {
    if (gRtlBitmapFns.initialize) {
        return;
    }

    FARPROC proc = load_ntdll_proc("RtlInitializeBitMap");
    TEST_CHECK(sizeof(gRtlBitmapFns.initialize) == sizeof(proc));
    memcpy(&gRtlBitmapFns.initialize, &proc, sizeof(gRtlBitmapFns.initialize));

    proc = load_ntdll_proc("RtlSetBits");
    TEST_CHECK(sizeof(gRtlBitmapFns.set_bits) == sizeof(proc));
    memcpy(&gRtlBitmapFns.set_bits, &proc, sizeof(gRtlBitmapFns.set_bits));

    proc = load_ntdll_proc("RtlAreBitsSet");
    TEST_CHECK(sizeof(gRtlBitmapFns.are_bits_set) == sizeof(proc));
    memcpy(&gRtlBitmapFns.are_bits_set, &proc, sizeof(gRtlBitmapFns.are_bits_set));

    proc = load_ntdll_proc("RtlAreBitsClear");
    TEST_CHECK(sizeof(gRtlBitmapFns.are_bits_clear) == sizeof(proc));
    memcpy(&gRtlBitmapFns.are_bits_clear, &proc, sizeof(gRtlBitmapFns.are_bits_clear));
}

static void test_initialize_sets_header(void) {
    ULONG buffer[2] = {0};
    TEST_RTL_BITMAP bitmap;
    memset(&bitmap, 0xCC, sizeof(bitmap));

    gRtlBitmapFns.initialize(&bitmap, buffer, 64);

    TEST_CHECK_EQ(64u, bitmap.SizeOfBitMap);
    TEST_CHECK(bitmap.Buffer == buffer);
}

static void test_set_bits_and_queries(void) {
    ULONG buffer[2] = {0};
    TEST_RTL_BITMAP bitmap;
    gRtlBitmapFns.initialize(&bitmap, buffer, 64);

    TEST_CHECK_EQ(FALSE, gRtlBitmapFns.are_bits_set(&bitmap, 1, 3));
    gRtlBitmapFns.set_bits(&bitmap, 1, 3);
    TEST_CHECK_EQ(TRUE, gRtlBitmapFns.are_bits_set(&bitmap, 1, 3));
    TEST_CHECK_EQ(FALSE, gRtlBitmapFns.are_bits_set(&bitmap, 0, 4));
    TEST_CHECK_EQ(FALSE, gRtlBitmapFns.are_bits_set(&bitmap, 0, 0));
    TEST_CHECK_EQ(TRUE, gRtlBitmapFns.are_bits_clear(&bitmap, 4, 4));
    TEST_CHECK_EQ(FALSE, gRtlBitmapFns.are_bits_clear(&bitmap, 4, 0));
    TEST_CHECK_EQ(FALSE, gRtlBitmapFns.are_bits_clear(&bitmap, 1, 1));

    TEST_CHECK_EQ(0x0000000Eu, buffer[0]);
    TEST_CHECK_EQ(0x00000000u, buffer[1]);

    ULONG snapshot = buffer[0];
    gRtlBitmapFns.set_bits(&bitmap, 0, 0);
    TEST_CHECK_EQ(snapshot, buffer[0]);

    TEST_CHECK_EQ(FALSE, gRtlBitmapFns.are_bits_set(&bitmap, 60, 8));
    TEST_CHECK_EQ(TRUE, gRtlBitmapFns.are_bits_clear(&bitmap, 8, 8));
}

static void test_are_bits_clear_after_setting(void) {
    ULONG buffer[2] = {0};
    TEST_RTL_BITMAP bitmap;
    gRtlBitmapFns.initialize(&bitmap, buffer, 64);

    TEST_CHECK_EQ(TRUE, gRtlBitmapFns.are_bits_clear(&bitmap, 16, 8));
    gRtlBitmapFns.set_bits(&bitmap, 16, 8);
    TEST_CHECK_EQ(FALSE, gRtlBitmapFns.are_bits_clear(&bitmap, 16, 8));
    TEST_CHECK_EQ(TRUE, gRtlBitmapFns.are_bits_set(&bitmap, 16, 8));
}

int main(void) {
    load_rtl_bitmap_functions();
    TEST_CHECK(gRtlBitmapFns.initialize);
    TEST_CHECK(gRtlBitmapFns.set_bits);
    TEST_CHECK(gRtlBitmapFns.are_bits_set);
    TEST_CHECK(gRtlBitmapFns.are_bits_clear);

    test_initialize_sets_header();
    test_set_bits_and_queries();
    test_are_bits_clear_after_setting();
    return 0;
}
