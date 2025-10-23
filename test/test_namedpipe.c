#include "test_assert.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string.h>

static const char *kPipeName = "\\\\.\\pipe\\wibo_test_namedpipe";
static const char *kPipeNameConnect = "\\\\.\\pipe\\wibo_test_namedpipe_connect";
static const char *kPipeNameNowait = "\\\\.\\pipe\\wibo_test_namedpipe_nowait";
static const char *kPipeNameOverlapped = "\\\\.\\pipe\\wibo_test_namedpipe_overlapped";

struct ConnectThreadArgs {
	const char *pipeName;
	const char *message;
	DWORD delayMs;
	HANDLE client;
	DWORD error;
};

static DWORD WINAPI client_connect_thread(LPVOID parameter) {
	struct ConnectThreadArgs *args = (struct ConnectThreadArgs *)parameter;
	args->client = INVALID_HANDLE_VALUE;
	args->error = ERROR_SUCCESS;
	if (args->delayMs) {
		Sleep(args->delayMs);
	}
	HANDLE client =
		CreateFileA(args->pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	args->client = client;
	if (client == INVALID_HANDLE_VALUE) {
		args->error = GetLastError();
		return 0;
	}
	if (args->message) {
		DWORD written = 0;
		WriteFile(client, args->message, (DWORD)strlen(args->message), &written, NULL);
	}
	return 0;
}

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

	HANDLE connectPipe = CreateNamedPipeA(kPipeNameConnect, PIPE_ACCESS_DUPLEX,
										  PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 1024, 1024, 0, NULL);
	TEST_CHECK(connectPipe != INVALID_HANDLE_VALUE);

	struct ConnectThreadArgs connectArgs = {
		.pipeName = kPipeNameConnect,
		.message = "hello",
		.delayMs = 50,
		.client = INVALID_HANDLE_VALUE,
		.error = ERROR_SUCCESS,
	};

	HANDLE connectThread = CreateThread(NULL, 0, client_connect_thread, &connectArgs, 0, NULL);
	TEST_CHECK(connectThread != NULL);
	TEST_CHECK(ConnectNamedPipe(connectPipe, NULL));
	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(connectThread, 5000));
	TEST_CHECK(CloseHandle(connectThread));
	TEST_CHECK(connectArgs.client != INVALID_HANDLE_VALUE);
	TEST_CHECK_EQ(ERROR_SUCCESS, connectArgs.error);

	read_checked(connectPipe, "hello");
	write_checked(connectPipe, "world");
	read_checked(connectArgs.client, "world");

	SetLastError(0xdeadbeefu);
	TEST_CHECK(!ConnectNamedPipe(connectPipe, NULL));
	TEST_CHECK_EQ(ERROR_PIPE_CONNECTED, GetLastError());

	TEST_CHECK(CloseHandle(connectArgs.client));
	TEST_CHECK(CloseHandle(connectPipe));

	HANDLE nowaitPipe = CreateNamedPipeA(kPipeNameNowait, PIPE_ACCESS_DUPLEX,
										 PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT, 1, 1024, 1024, 0, NULL);
	TEST_CHECK(nowaitPipe != INVALID_HANDLE_VALUE);
	SetLastError(0xdeadbeefu);
	TEST_CHECK(!ConnectNamedPipe(nowaitPipe, NULL));
	TEST_CHECK_EQ(ERROR_PIPE_LISTENING, GetLastError());
	TEST_CHECK(CloseHandle(nowaitPipe));

	HANDLE overlappedPipe = CreateNamedPipeA(kPipeNameOverlapped, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
											 PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 1024, 1024, 0, NULL);
	TEST_CHECK(overlappedPipe != INVALID_HANDLE_VALUE);

	struct ConnectThreadArgs overlappedArgs = {
		.pipeName = kPipeNameOverlapped,
		.message = NULL,
		.delayMs = 50,
		.client = INVALID_HANDLE_VALUE,
		.error = ERROR_SUCCESS,
	};

	OVERLAPPED ov = {0};
	ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
	TEST_CHECK(ov.hEvent != NULL);

	HANDLE overlappedThread = CreateThread(NULL, 0, client_connect_thread, &overlappedArgs, 0, NULL);
	TEST_CHECK(overlappedThread != NULL);

	SetLastError(0xdeadbeefu);
	TEST_CHECK(!ConnectNamedPipe(overlappedPipe, &ov));
	TEST_CHECK_EQ(ERROR_IO_PENDING, GetLastError());

	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(overlappedThread, 5000));
	TEST_CHECK(CloseHandle(overlappedThread));
	TEST_CHECK(overlappedArgs.client != INVALID_HANDLE_VALUE);
	TEST_CHECK_EQ(ERROR_SUCCESS, overlappedArgs.error);

	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(ov.hEvent, 5000));

	DWORD transferred = 0;
	TEST_CHECK(GetOverlappedResult(overlappedPipe, &ov, &transferred, FALSE));
	TEST_CHECK_EQ((DWORD)0, transferred);

	TEST_CHECK(CloseHandle(overlappedArgs.client));
	TEST_CHECK(CloseHandle(ov.hEvent));
	TEST_CHECK(CloseHandle(overlappedPipe));

	return 0;
}
