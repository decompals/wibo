#include <windows.h>
#include <stdint.h>
#include <stdlib.h>

#include "test_assert.h"

static SIZE_T query_page_size(void) {
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return info.dwPageSize;
}

int main(void) {
    const SIZE_T page = query_page_size();

    uint8_t *reserved = (uint8_t *)VirtualAlloc(NULL, page * 2, MEM_RESERVE, PAGE_READWRITE);
    TEST_CHECK(reserved != NULL);
    TEST_CHECK(((uintptr_t)reserved % (64 * 1024)) == 0);

    uint8_t *reserveCommit = (uint8_t *)VirtualAlloc(NULL, page, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    TEST_CHECK(reserveCommit != NULL);
    TEST_CHECK(((uintptr_t)reserveCommit % (64 * 1024)) == 0);
    reserveCommit[page - 1] = 0x77;
    TEST_CHECK(VirtualFree(reserveCommit, 0, MEM_RELEASE));

    uint8_t *directCommit = (uint8_t *)VirtualAlloc(NULL, page, MEM_COMMIT, PAGE_READWRITE);
    TEST_CHECK(directCommit != NULL);
    TEST_CHECK(((uintptr_t)directCommit % (64 * 1024)) == 0);
    directCommit[0] = 0x55;
    directCommit[page - 1] = 0x66;
    TEST_CHECK(VirtualFree(directCommit, 0, MEM_RELEASE));

    MEMORY_BASIC_INFORMATION mbi;
    TEST_CHECK_EQ(sizeof(mbi), VirtualQuery(reserved, &mbi, sizeof(mbi)));
    TEST_CHECK_EQ((uintptr_t)reserved, (uintptr_t)mbi.BaseAddress);
    TEST_CHECK_EQ((uintptr_t)reserved, (uintptr_t)mbi.AllocationBase);
    TEST_CHECK_EQ(PAGE_READWRITE, mbi.AllocationProtect);
    TEST_CHECK_EQ(page * 2, mbi.RegionSize);
    TEST_CHECK_EQ(MEM_RESERVE, mbi.State);
    TEST_CHECK(mbi.Protect == 0 || mbi.Protect == PAGE_NOACCESS);
    TEST_CHECK_EQ(MEM_PRIVATE, mbi.Type);

    uint8_t *first = (uint8_t *)VirtualAlloc(reserved, page, MEM_COMMIT, PAGE_READWRITE);
    TEST_CHECK(first == reserved);
    first[0] = 0xAB;
    first[page - 1] = 0xCD;

    TEST_CHECK_EQ(sizeof(mbi), VirtualQuery(reserved, &mbi, sizeof(mbi)));
    TEST_CHECK_EQ((uintptr_t)reserved, (uintptr_t)mbi.BaseAddress);
    TEST_CHECK_EQ(MEM_COMMIT, mbi.State);
    TEST_CHECK_EQ(page, mbi.RegionSize);
    TEST_CHECK_EQ(PAGE_READWRITE, mbi.Protect);

    TEST_CHECK_EQ(sizeof(mbi), VirtualQuery(reserved + page, &mbi, sizeof(mbi)));
    TEST_CHECK_EQ((uintptr_t)(reserved + page), (uintptr_t)mbi.BaseAddress);
    TEST_CHECK_EQ(MEM_RESERVE, mbi.State);
    TEST_CHECK_EQ(page, mbi.RegionSize);
    TEST_CHECK(mbi.Protect == 0 || mbi.Protect == PAGE_NOACCESS);

    uint8_t *second = (uint8_t *)VirtualAlloc(reserved + page, page, MEM_COMMIT, PAGE_READONLY);
    TEST_CHECK(second == reserved + page);

    TEST_CHECK_EQ(sizeof(mbi), VirtualQuery(reserved + page, &mbi, sizeof(mbi)));
    TEST_CHECK_EQ(MEM_COMMIT, mbi.State);
    TEST_CHECK_EQ(PAGE_READONLY, mbi.Protect);

    DWORD oldProtect = 0;
    TEST_CHECK(VirtualProtect(second, page, PAGE_READWRITE, &oldProtect));
    TEST_CHECK_EQ(PAGE_READONLY, oldProtect);
    TEST_CHECK_EQ(sizeof(mbi), VirtualQuery(second, &mbi, sizeof(mbi)));
    TEST_CHECK_EQ(PAGE_READWRITE, mbi.Protect);

    TEST_CHECK(VirtualFree(second, page, MEM_DECOMMIT));

    SetLastError(0);
    TEST_CHECK(!VirtualProtect(second, page, PAGE_READWRITE, NULL));
    TEST_CHECK_EQ(ERROR_NOACCESS, GetLastError());

    TEST_CHECK_EQ(sizeof(mbi), VirtualQuery(second, &mbi, sizeof(mbi)));
    TEST_CHECK_EQ(MEM_RESERVE, mbi.State);
    TEST_CHECK(mbi.Protect == 0 || mbi.Protect == PAGE_NOACCESS);

    TEST_CHECK(VirtualFree(first, page, MEM_DECOMMIT));

    uint8_t *recommit = (uint8_t *)VirtualAlloc(reserved, page, MEM_COMMIT, PAGE_READWRITE);
    TEST_CHECK(recommit == reserved);
    for (SIZE_T i = 0; i < page; ++i) {
        TEST_CHECK(recommit[i] == 0);
    }

    SetLastError(0);
    TEST_CHECK(!VirtualFree(reserved + page, page, MEM_RELEASE));
    TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());

    SetLastError(0);
    TEST_CHECK(!VirtualFree(reserved + page, 0, MEM_RELEASE));
    TEST_CHECK_EQ(ERROR_INVALID_ADDRESS, GetLastError());

    TEST_CHECK(VirtualFree(reserved, 0, MEM_RELEASE));

    SetLastError(0);
    TEST_CHECK(VirtualAlloc(reserved, page, MEM_COMMIT, PAGE_READWRITE) == NULL);
    TEST_CHECK_EQ(ERROR_INVALID_ADDRESS, GetLastError());

    return EXIT_SUCCESS;
}
