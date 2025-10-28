#include "wincon.h"

#include "context.h"
#include "errors.h"
#include "files.h"
#include "handles.h"
#include "strutil.h"

namespace kernel32 {

BOOL WIN_FUNC GetConsoleMode(HANDLE hConsoleHandle, LPDWORD lpMode) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: GetConsoleMode(%p)\n", hConsoleHandle);
	if (lpMode) {
		*lpMode = 0;
	}
	return TRUE;
}

BOOL WIN_FUNC SetConsoleMode(HANDLE hConsoleHandle, DWORD dwMode) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: SetConsoleMode(%p, 0x%x)\n", hConsoleHandle, dwMode);
	(void)hConsoleHandle;
	(void)dwMode;
	return TRUE;
}

UINT WIN_FUNC GetConsoleCP() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: GetConsoleCP() -> 65001\n");
	return 65001; // UTF-8
}

UINT WIN_FUNC GetConsoleOutputCP() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: GetConsoleOutputCP() -> 65001\n");
	return 65001; // UTF-8
}

BOOL WIN_FUNC SetConsoleCtrlHandler(PHANDLER_ROUTINE HandlerRoutine, BOOL Add) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: SetConsoleCtrlHandler(%p, %u)\n", reinterpret_cast<const void *>(HandlerRoutine), Add);
	(void)HandlerRoutine;
	(void)Add;
	return TRUE;
}

BOOL WIN_FUNC GetConsoleScreenBufferInfo(HANDLE hConsoleOutput, CONSOLE_SCREEN_BUFFER_INFO *lpConsoleScreenBufferInfo) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: GetConsoleScreenBufferInfo(%p, %p)\n", hConsoleOutput, lpConsoleScreenBufferInfo);
	(void)hConsoleOutput;
	if (!lpConsoleScreenBufferInfo) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	lpConsoleScreenBufferInfo->dwSize = {80, 25};
	lpConsoleScreenBufferInfo->dwCursorPosition = {0, 0};
	lpConsoleScreenBufferInfo->wAttributes = 0;
	lpConsoleScreenBufferInfo->srWindow = {0, 0, 79, 24};
	lpConsoleScreenBufferInfo->dwMaximumWindowSize = {80, 25};
	return TRUE;
}

BOOL WIN_FUNC WriteConsoleW(HANDLE hConsoleOutput, LPCVOID lpBuffer, DWORD nNumberOfCharsToWrite,
							LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("WriteConsoleW(%p, %p, %u, %p, %p)\n", hConsoleOutput, lpBuffer, nNumberOfCharsToWrite,
			  lpNumberOfCharsWritten, lpReserved);
	(void)lpReserved;
	if (lpNumberOfCharsWritten) {
		*lpNumberOfCharsWritten = 0;
	}
	if (!lpBuffer && nNumberOfCharsToWrite != 0) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	auto file = wibo::handles().getAs<FileObject>(hConsoleOutput);
	if (file->fd == STDOUT_FILENO || file->fd == STDERR_FILENO) {
		auto str = wideStringToString(static_cast<const uint16_t *>(lpBuffer), static_cast<int>(nNumberOfCharsToWrite));
		dprintf(file->fd, "%s", str.c_str());
		if (lpNumberOfCharsWritten) {
			*lpNumberOfCharsWritten = nNumberOfCharsToWrite;
		}
		return TRUE;
	}

	setLastError(ERROR_INVALID_HANDLE);
	return FALSE;
}

DWORD WIN_FUNC GetConsoleTitleA(LPSTR lpConsoleTitle, DWORD nSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetConsoleTitleA(%p, %u)\n", lpConsoleTitle, nSize);
	if (lpConsoleTitle && nSize > 0) {
		lpConsoleTitle[0] = '\0';
	}
	setLastError(ERROR_SUCCESS);
	return 0;
}

DWORD WIN_FUNC GetConsoleTitleW(LPWSTR lpConsoleTitle, DWORD nSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetConsoleTitleW(%p, %u)\n", lpConsoleTitle, nSize);
	if (lpConsoleTitle && nSize > 0) {
		lpConsoleTitle[0] = 0;
	}
	setLastError(ERROR_SUCCESS);
	return 0;
}

BOOL WIN_FUNC PeekConsoleInputA(HANDLE hConsoleInput, INPUT_RECORD *lpBuffer, DWORD nLength,
								LPDWORD lpNumberOfEventsRead) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: PeekConsoleInputA(%p, %p, %u)\n", hConsoleInput, lpBuffer, nLength);
	(void)hConsoleInput;
	(void)lpBuffer;
	(void)nLength;
	if (lpNumberOfEventsRead) {
		*lpNumberOfEventsRead = 0;
	}
	return TRUE;
}

BOOL WIN_FUNC ReadConsoleInputA(HANDLE hConsoleInput, INPUT_RECORD *lpBuffer, DWORD nLength,
								LPDWORD lpNumberOfEventsRead) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: ReadConsoleInputA(%p, %p, %u)\n", hConsoleInput, lpBuffer, nLength);
	(void)hConsoleInput;
	(void)lpBuffer;
	(void)nLength;
	if (lpNumberOfEventsRead) {
		*lpNumberOfEventsRead = 0;
	}
	return TRUE;
}

} // namespace kernel32
