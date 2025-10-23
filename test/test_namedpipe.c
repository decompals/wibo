#include "test_assert.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string.h>

static const char *kPipeName = "\\\\.\\pipe\\wibo_test_namedpipe";

static void write_checked(HANDLE handle, const char *msg) {
	DWORD written = 0;
	TEST_CHECK(WriteFile(handle, msg, (DWORD)strlen(msg), &written, NULL));
	TEST_CHECK_EQ((DWORD)strlen(msg), written);
}

static void read_checked(HANDLE handle, const char *expected) {
	char buffer[64] = {0};
	DWORD read = 0;
	TEST_CHECK(ReadFile(handle, buffer, sizeof(buffer), &read, NULL));
	TEST_CHECK_EQ((DWORD)strlen(expected), read);
	TEST_CHECK(memcmp(buffer, expected, read) == 0);
}

int main(void) {
	SetLastError(0xdeadbeefu);
	HANDLE missing = CreateFileA(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	TEST_CHECK(missing == INVALID_HANDLE_VALUE);
	TEST_CHECK_EQ(ERROR_FILE_NOT_FOUND, GetLastError());

	HANDLE pipe = CreateNamedPipeA(kPipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1,
								   1024, 1024, 0, NULL);
	TEST_CHECK(pipe != INVALID_HANDLE_VALUE);

	HANDLE client =
		CreateFileA(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	TEST_CHECK(client != INVALID_HANDLE_VALUE);

	write_checked(client, "ping");
	read_checked(pipe, "ping");

	write_checked(pipe, "pong");
	read_checked(client, "pong");

	HANDLE invalidPrefix = CreateNamedPipeA("\\\\.\\pipe\\", PIPE_ACCESS_DUPLEX,
											PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 1024, 1024, 0, NULL);
	TEST_CHECK(invalidPrefix == INVALID_HANDLE_VALUE);
	TEST_CHECK_EQ(ERROR_INVALID_HANDLE, GetLastError());

	SetLastError(0xdeadbeefu);
	HANDLE busy = CreateFileA(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	TEST_CHECK(busy == INVALID_HANDLE_VALUE);
	TEST_CHECK_EQ(ERROR_PIPE_BUSY, GetLastError());

	SetLastError(0xdeadbeefu);
	HANDLE invalidName = CreateNamedPipeA("invalid", PIPE_ACCESS_DUPLEX,
										  PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 1024, 1024, 0, NULL);
	TEST_CHECK(invalidName == INVALID_HANDLE_VALUE);
	TEST_CHECK_EQ(ERROR_INVALID_NAME, GetLastError());

	HANDLE badMode = CreateNamedPipeA(kPipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
									  1, 1024, 1024, 0, NULL);
	TEST_CHECK(badMode == INVALID_HANDLE_VALUE);
	TEST_CHECK_EQ(ERROR_INVALID_PARAMETER, GetLastError());

	HANDLE nullName = CreateNamedPipeA(NULL, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1,
									   1024, 1024, 0, NULL);
	TEST_CHECK(nullName == INVALID_HANDLE_VALUE);
	TEST_CHECK_EQ(ERROR_PATH_NOT_FOUND, GetLastError());

	TEST_CHECK(CloseHandle(client));
	TEST_CHECK(CloseHandle(pipe));

	return 0;
}
