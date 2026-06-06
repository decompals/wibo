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

	TEST_CHECK(SetFilePointer(file, mapping_size - 1, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER);
	uint8_t value = 0;
	DWORD bytes_read = 0;
	TEST_CHECK(ReadFile(file, &value, sizeof(value), &bytes_read, NULL));
	TEST_CHECK_EQ(1u, bytes_read);
	TEST_CHECK_EQ(0x5au, value);

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

int main(void) {
	test_readwrite_mapping_extends_file();
	test_zero_size_file_mapping_fails();
	test_zero_size_pagefile_mapping_fails();
	return 0;
}
