#include <windows.h>

#include <stdint.h>
#include <stdio.h>

#include "test_assert.h"

static const char kTempFileName[] = "test_createfilemapping.tmp";

static DWORD checked_file_size(HANDLE file) {
	DWORD high = 0;
	DWORD low = GetFileSize(file, &high);
	TEST_CHECK_MSG(low != INVALID_FILE_SIZE || GetLastError() == NO_ERROR, "GetFileSize failed: %lu", GetLastError());
	TEST_CHECK_EQ(0u, high);
	return low;
}

static HANDLE create_temp_file(void) {
	HANDLE file = CreateFileA(kTempFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
							  FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
	TEST_CHECK_MSG(file != INVALID_HANDLE_VALUE, "CreateFileA failed: %lu", GetLastError());
	return file;
}

static void write_byte_at(HANDLE file, DWORD offset, uint8_t value) {
	DWORD bytes_written = 0;
	TEST_CHECK(SetFilePointer(file, offset, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER);
	TEST_CHECK(WriteFile(file, &value, sizeof(value), &bytes_written, NULL));
	TEST_CHECK_EQ(1u, bytes_written);
}

static uint8_t read_byte_at(HANDLE file, DWORD offset) {
	uint8_t value = 0;
	DWORD bytes_read = 0;
	TEST_CHECK(SetFilePointer(file, offset, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER);
	TEST_CHECK(ReadFile(file, &value, sizeof(value), &bytes_read, NULL));
	TEST_CHECK_EQ(1u, bytes_read);
	return value;
}

static void test_readwrite_mapping_extends_file(void) {
	const DWORD mapping_size = 262144;
	HANDLE file = create_temp_file();
	TEST_CHECK_EQ(0u, checked_file_size(file));

	HANDLE mapping = CreateFileMappingA(file, NULL, PAGE_READWRITE, 0, mapping_size, NULL);
	TEST_CHECK_MSG(mapping != NULL, "CreateFileMappingA(PAGE_READWRITE) failed: %lu", GetLastError());
	TEST_CHECK_EQ(mapping_size, checked_file_size(file));

	uint8_t *view = (uint8_t *)MapViewOfFileEx(mapping, FILE_MAP_ALL_ACCESS, 0, 0, mapping_size, NULL);
	TEST_CHECK_MSG(view != NULL, "MapViewOfFileEx failed: %lu", GetLastError());
	view[0] = 0x11;
	view[mapping_size - 1] = 0x5a;
	TEST_CHECK(FlushViewOfFile(view, mapping_size));
	TEST_CHECK(UnmapViewOfFile(view));
	TEST_CHECK(CloseHandle(mapping));

	TEST_CHECK_EQ(0x11u, read_byte_at(file, 0));
	TEST_CHECK_EQ(0x5au, read_byte_at(file, mapping_size - 1));

	TEST_CHECK(CloseHandle(file));
	TEST_CHECK(GetFileAttributesA(kTempFileName) == INVALID_FILE_ATTRIBUTES);
}

static void test_copy_mapping_does_not_write_file(void) {
	const DWORD mapping_size = 4096;
	HANDLE file = create_temp_file();
	write_byte_at(file, 0, 0x24);

	HANDLE mapping = CreateFileMappingA(file, NULL, PAGE_READWRITE, 0, mapping_size, NULL);
	TEST_CHECK_MSG(mapping != NULL, "CreateFileMappingA(PAGE_READWRITE) failed: %lu", GetLastError());

	uint8_t *view = (uint8_t *)MapViewOfFileEx(mapping, FILE_MAP_COPY, 0, 0, mapping_size, NULL);
	TEST_CHECK_MSG(view != NULL, "MapViewOfFileEx(FILE_MAP_COPY) failed: %lu", GetLastError());
	TEST_CHECK_EQ(0x24u, view[0]);
	view[0] = 0xa5;
	view[mapping_size - 1] = 0x5c;
	TEST_CHECK(UnmapViewOfFile(view));
	TEST_CHECK(CloseHandle(mapping));

	TEST_CHECK_EQ(0x24u, read_byte_at(file, 0));
	TEST_CHECK_EQ(0x00u, read_byte_at(file, mapping_size - 1));

	TEST_CHECK(CloseHandle(file));
	TEST_CHECK(GetFileAttributesA(kTempFileName) == INVALID_FILE_ATTRIBUTES);
}

static void test_zero_size_file_mapping_fails(void) {
	HANDLE file = create_temp_file();
	SetLastError(0xdeadbeef);
	HANDLE mapping = CreateFileMappingA(file, NULL, PAGE_READONLY, 0, 0, NULL);
	TEST_CHECK(mapping == NULL);
	TEST_CHECK_EQ(ERROR_FILE_INVALID, GetLastError());
	TEST_CHECK(CloseHandle(file));
	TEST_CHECK(GetFileAttributesA(kTempFileName) == INVALID_FILE_ATTRIBUTES);
}

static void test_zero_size_pagefile_mapping_fails(void) {
	SetLastError(0xdeadbeef);
	HANDLE mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0, NULL);
	TEST_CHECK(mapping == NULL);
	TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());
}

static void test_fixed_address_view_is_not_reallocated(void) {
	// Not a multiple of the 64 KiB allocation granularity, so the view ends partway through a granule.
	const DWORD mapping_size = 0x23000;
	HANDLE file = create_temp_file();
	HANDLE mapping = CreateFileMappingA(file, NULL, PAGE_READWRITE, 0, mapping_size, NULL);
	TEST_CHECK_MSG(mapping != NULL, "CreateFileMappingA(PAGE_READWRITE) failed: %lu", GetLastError());

	// Find a free address by reserving a range and releasing it, then map the view there.
	uint8_t *base = (uint8_t *)VirtualAlloc(NULL, mapping_size, MEM_RESERVE, PAGE_NOACCESS);
	TEST_CHECK_MSG(base != NULL, "VirtualAlloc(MEM_RESERVE) failed: %lu", GetLastError());
	TEST_CHECK(VirtualFree(base, 0, MEM_RELEASE));
	uint8_t *view = (uint8_t *)MapViewOfFileEx(mapping, FILE_MAP_ALL_ACCESS, 0, 0, mapping_size, base);
	TEST_CHECK_MSG(view == base, "MapViewOfFileEx at %p failed: %lu", base, GetLastError());
	view[0] = 0x3c;
	view[mapping_size - 1] = 0xc3;

	uint8_t *block = (uint8_t *)VirtualAlloc(NULL, mapping_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	TEST_CHECK_MSG(block != NULL, "VirtualAlloc failed: %lu", GetLastError());
	TEST_CHECK_MSG(block + mapping_size <= view || block >= view + mapping_size,
				   "VirtualAlloc returned %p, overlapping the view at %p", block, view);
	block[0] = 0xff;
	block[mapping_size - 1] = 0xff;
	TEST_CHECK(VirtualFree(block, 0, MEM_RELEASE));
	TEST_CHECK_EQ(0x3cu, view[0]);
	TEST_CHECK_EQ(0xc3u, view[mapping_size - 1]);

	SetLastError(0xdeadbeef);
	TEST_CHECK(VirtualAlloc(base, mapping_size, MEM_RESERVE, PAGE_NOACCESS) == NULL);
	TEST_CHECK_EQ(ERROR_INVALID_ADDRESS, GetLastError());
	SetLastError(0xdeadbeef);
	TEST_CHECK(MapViewOfFileEx(mapping, FILE_MAP_ALL_ACCESS, 0, 0, mapping_size, base) == NULL);
	TEST_CHECK_EQ(ERROR_INVALID_ADDRESS, GetLastError());

	TEST_CHECK(UnmapViewOfFile(view));
	uint8_t *reserved = (uint8_t *)VirtualAlloc(base, mapping_size, MEM_RESERVE, PAGE_NOACCESS);
	TEST_CHECK_MSG(reserved == base, "VirtualAlloc(MEM_RESERVE) at %p after unmapping returned %p: %lu", base, reserved,
				   GetLastError());
	TEST_CHECK(VirtualFree(reserved, 0, MEM_RELEASE));

	TEST_CHECK(CloseHandle(mapping));
	TEST_CHECK(CloseHandle(file));
}

static void test_fixed_address_view_does_not_replace_allocation(void) {
	const DWORD granularity = 0x10000;
	const DWORD mapping_size = 2 * granularity;
	HANDLE file = create_temp_file();
	HANDLE mapping = CreateFileMappingA(file, NULL, PAGE_READWRITE, 0, mapping_size, NULL);
	TEST_CHECK_MSG(mapping != NULL, "CreateFileMappingA(PAGE_READWRITE) failed: %lu", GetLastError());

	uint8_t *block = (uint8_t *)VirtualAlloc(NULL, mapping_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	TEST_CHECK_MSG(block != NULL, "VirtualAlloc failed: %lu", GetLastError());
	block[0] = 0x42;
	block[mapping_size - 1] = 0x24;
	SetLastError(0xdeadbeef);
	TEST_CHECK(MapViewOfFileEx(mapping, FILE_MAP_ALL_ACCESS, 0, 0, mapping_size, block) == NULL);
	TEST_CHECK_EQ(ERROR_INVALID_ADDRESS, GetLastError());
	TEST_CHECK_EQ(0x42u, block[0]);
	TEST_CHECK_EQ(0x24u, block[mapping_size - 1]);
	TEST_CHECK(VirtualFree(block, 0, MEM_RELEASE));

	// The start of the range is free, but the rest is still allocated.
	uint8_t *tail = (uint8_t *)VirtualAlloc(block + granularity, granularity, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	TEST_CHECK_MSG(tail == block + granularity, "VirtualAlloc at %p returned %p: %lu", block + granularity, tail,
				   GetLastError());
	tail[0] = 0x5a;
	SetLastError(0xdeadbeef);
	TEST_CHECK(MapViewOfFileEx(mapping, FILE_MAP_ALL_ACCESS, 0, 0, mapping_size, block) == NULL);
	TEST_CHECK_EQ(ERROR_INVALID_ADDRESS, GetLastError());
	TEST_CHECK_EQ(0x5au, tail[0]);
	TEST_CHECK(VirtualFree(tail, 0, MEM_RELEASE));

	TEST_CHECK(CloseHandle(mapping));
	TEST_CHECK(CloseHandle(file));
}

static void test_fixed_address_view_above_2gb_fails(void) {
	// Not large-address-aware, so user addresses end at 0x7FFEFFFF. Wine maps the view anyway; Windows refuses it.
	uint8_t *const base = (uint8_t *)0x80000000u;
	const DWORD mapping_size = 0x10000;
	HANDLE file = create_temp_file();
	HANDLE mapping = CreateFileMappingA(file, NULL, PAGE_READWRITE, 0, mapping_size, NULL);
	TEST_CHECK_MSG(mapping != NULL, "CreateFileMappingA(PAGE_READWRITE) failed: %lu", GetLastError());

	SetLastError(0xdeadbeef);
	uint8_t *view = (uint8_t *)MapViewOfFileEx(mapping, FILE_MAP_ALL_ACCESS, 0, 0, mapping_size, base);
	TEST_CHECK_MSG(view == NULL, "MapViewOfFileEx at %p returned %p", base, view);
	TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());

	TEST_CHECK(CloseHandle(mapping));
	TEST_CHECK(CloseHandle(file));
}

int main(void) {
	test_readwrite_mapping_extends_file();
	test_copy_mapping_does_not_write_file();
	test_zero_size_file_mapping_fails();
	test_zero_size_pagefile_mapping_fails();
	test_fixed_address_view_is_not_reallocated();
	test_fixed_address_view_does_not_replace_allocation();
	test_fixed_address_view_above_2gb_fails();
	return 0;
}
