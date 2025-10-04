#include <windows.h>

#include <stdint.h>
#include <stdio.h>

#include "test_assert.h"

static SIZE_T query_page_size(void) {
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return info.dwPageSize;
}

static void test_null_address(void) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T got = VirtualQuery(NULL, &mbi, sizeof(mbi));
    TEST_CHECK_EQ(sizeof(mbi), got);
    TEST_CHECK(mbi.BaseAddress == (PVOID)0);
    TEST_CHECK(mbi.AllocationBase == NULL);
    TEST_CHECK_EQ(0u, mbi.AllocationProtect);
    TEST_CHECK_EQ(MEM_FREE, mbi.State);
    TEST_CHECK_EQ(PAGE_NOACCESS, mbi.Protect);
    TEST_CHECK_EQ(0u, mbi.Type);
    TEST_CHECK(mbi.RegionSize >= query_page_size());
}

static void test_module_region(void) {
    MEMORY_BASIC_INFORMATION mbi;
    void *address = (void *)&test_module_region;
    SIZE_T got = VirtualQuery(address, &mbi, sizeof(mbi));
    TEST_CHECK_EQ(sizeof(mbi), got);
    TEST_CHECK_EQ(MEM_COMMIT, mbi.State);
    TEST_CHECK_EQ(MEM_IMAGE, mbi.Type);
    TEST_CHECK(mbi.RegionSize >= query_page_size());
    HMODULE module = GetModuleHandleA(NULL);
    TEST_CHECK(module != NULL);
    TEST_CHECK((HMODULE)mbi.AllocationBase == module);
    TEST_CHECK(mbi.AllocationProtect != 0);
    TEST_CHECK((mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0);
    TEST_CHECK((uintptr_t)address >= (uintptr_t)mbi.BaseAddress);
    TEST_CHECK((uintptr_t)address < (uintptr_t)mbi.BaseAddress + mbi.RegionSize);
}

static void test_anonymous_mapping(void) {
    const SIZE_T page = query_page_size();
    HANDLE mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, (DWORD)page, NULL);
    TEST_CHECK(mapping != NULL);
    uint8_t *view = (uint8_t *)MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, page);
    TEST_CHECK(view != NULL);

    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T got = VirtualQuery(view, &mbi, sizeof(mbi));
    TEST_CHECK_EQ(sizeof(mbi), got);
    TEST_CHECK_EQ(MEM_COMMIT, mbi.State);
    TEST_CHECK_EQ(MEM_MAPPED, mbi.Type);
    TEST_CHECK_EQ(PAGE_READWRITE, mbi.AllocationProtect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE));
    TEST_CHECK_EQ(PAGE_READWRITE, mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE));
    TEST_CHECK(mbi.RegionSize >= page);
    TEST_CHECK((uint8_t *)mbi.BaseAddress == view);
    TEST_CHECK((uint8_t *)mbi.AllocationBase == view);

    TEST_CHECK(UnmapViewOfFile(view));
    TEST_CHECK(CloseHandle(mapping));
}

static void test_file_mapping(void) {
    const SIZE_T page = query_page_size();
    HANDLE file = CreateFileA("test_virtualquery.tmp", GENERIC_READ | GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    TEST_CHECK(file != INVALID_HANDLE_VALUE);

    DWORD newPos = SetFilePointer(file, (LONG)page, NULL, FILE_BEGIN);
    TEST_CHECK(newPos != INVALID_SET_FILE_POINTER);
    TEST_CHECK(SetEndOfFile(file));
    TEST_CHECK(SetFilePointer(file, 0, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER);

    HANDLE mapping = CreateFileMappingA(file, NULL, PAGE_READONLY, 0, 0, NULL);
    TEST_CHECK(mapping != NULL);
    const uint8_t *view = (const uint8_t *)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    TEST_CHECK(view != NULL);

    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T got = VirtualQuery(view, &mbi, sizeof(mbi));
    TEST_CHECK_EQ(sizeof(mbi), got);
    TEST_CHECK_EQ(MEM_COMMIT, mbi.State);
    TEST_CHECK_EQ(MEM_MAPPED, mbi.Type);
    TEST_CHECK_EQ(PAGE_READONLY, mbi.AllocationProtect & (PAGE_READONLY | PAGE_EXECUTE_READ));
    TEST_CHECK_EQ(PAGE_READONLY, mbi.Protect & (PAGE_READONLY | PAGE_EXECUTE_READ));
    TEST_CHECK(mbi.RegionSize >= page);
    TEST_CHECK((const uint8_t *)mbi.BaseAddress == view);
    TEST_CHECK((const uint8_t *)mbi.AllocationBase == view);

    TEST_CHECK(UnmapViewOfFile(view));
    TEST_CHECK(CloseHandle(mapping));
    TEST_CHECK(CloseHandle(file));
    TEST_CHECK(GetFileAttributesA("test_virtualquery.tmp") == INVALID_FILE_ATTRIBUTES);
}

int main(void) {
    test_null_address();
    test_module_region();
    test_anonymous_mapping();
    test_file_mapping();
    return 0;
}
