#include "test_assert.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static DWORD parse_exit_code(const char *value) {
	TEST_CHECK(value != NULL);
	DWORD result = 0;
	for (const char *p = value; *p; ++p) {
		TEST_CHECK(*p >= '0' && *p <= '9');
		result = result * 10u + (DWORD)(*p - '0');
	}
	return result;
}

static int child_main(int argc, char **argv) {
	TEST_CHECK(argc >= 2);
	(void)argv;

	char exitBuffer[16];
	DWORD exitLen = GetEnvironmentVariableA("WIBO_TEST_PROC_EXIT", exitBuffer, sizeof(exitBuffer));
	TEST_CHECK(exitLen > 0 && exitLen < sizeof(exitBuffer));
	DWORD desiredExit = parse_exit_code(exitBuffer);

	Sleep(200);
	return (int)desiredExit;
}

static void test_createprocess_failure(void) {
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	SetLastError(0);
	char bogusCommandLine[] = "child";
	TEST_CHECK(
		!CreateProcessA("Z:/definitely/missing.exe", bogusCommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi));
	DWORD error = GetLastError();
	TEST_CHECK_MSG(error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND, "CreateProcessA missing file -> %lu",
				   (unsigned long)error);
}

static int parent_main(void) {
	test_createprocess_failure();

	char modulePath[MAX_PATH];
	DWORD pathLen = GetModuleFileNameA(NULL, modulePath, (DWORD)sizeof(modulePath));
	TEST_CHECK(pathLen > 0 && pathLen < sizeof(modulePath));

	const DWORD childExitCode = 0x24u;
	char commandLine[256];
	snprintf(commandLine, sizeof(commandLine), "child placeholder %lu", (unsigned long)childExitCode);

	char exitEnv[16];
	snprintf(exitEnv, sizeof(exitEnv), "%lu", (unsigned long)childExitCode);
	TEST_CHECK(SetEnvironmentVariableA("WIBO_TEST_PROC_EXIT", exitEnv));
	TEST_CHECK(SetEnvironmentVariableA("WIBO_TEST_PROC_ROLE", "child"));

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	GetStartupInfoA(&si);
	ZeroMemory(&pi, sizeof(pi));

	TEST_CHECK(CreateProcessA(modulePath, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi));
	TEST_CHECK(pi.hProcess != NULL);
	SetEnvironmentVariableA("WIBO_TEST_PROC_EXIT", NULL);
	SetEnvironmentVariableA("WIBO_TEST_PROC_ROLE", NULL);

	HANDLE processHandle = NULL;
	TEST_CHECK(DuplicateHandle(GetCurrentProcess(), pi.hProcess, GetCurrentProcess(), &processHandle, 0, FALSE,
							   DUPLICATE_SAME_ACCESS));
	TEST_CHECK(processHandle != NULL);
	TEST_CHECK(processHandle != pi.hProcess);

	TEST_CHECK(CloseHandle(pi.hProcess));
	TEST_CHECK_EQ(WAIT_FAILED, WaitForSingleObject(pi.hProcess, 0));
	pi.hProcess = NULL;

	Sleep(50);

	TEST_CHECK_EQ(WAIT_TIMEOUT, WaitForSingleObject(processHandle, 0));

	DWORD exitCode = 0;
	TEST_CHECK(GetExitCodeProcess(processHandle, &exitCode));
	TEST_CHECK_EQ(STILL_ACTIVE, exitCode);

	TEST_CHECK_EQ(WAIT_OBJECT_0, WaitForSingleObject(processHandle, 5000));

	TEST_CHECK(GetExitCodeProcess(processHandle, &exitCode));
	TEST_CHECK_EQ(childExitCode, exitCode);

	TEST_CHECK(CloseHandle(processHandle));
	if (pi.hThread) {
		TEST_CHECK(CloseHandle(pi.hThread));
	}

	return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
	char role[16];
	DWORD roleLen = GetEnvironmentVariableA("WIBO_TEST_PROC_ROLE", role, sizeof(role));
	if (roleLen > 0 && roleLen < sizeof(role) && strcmp(role, "child") == 0) {
		return child_main(argc, argv);
	}
	if (argc > 1 && strcmp(argv[1], "child") == 0) {
		return child_main(argc, argv);
	}
	return parent_main();
}
