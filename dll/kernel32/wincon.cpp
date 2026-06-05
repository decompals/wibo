#include "wincon.h"

#include "context.h"
#include "errors.h"
#include "files.h"
#include "handles.h"
#include "strutil.h"

#include <unistd.h>

namespace {

Pin<kernel32::FileObject> getValidFileHandle(HANDLE handle) {
	auto file = wibo::handles().getAs<kernel32::FileObject>(handle);
	if (!file || !file->valid()) {
		return {};
	}
	return file;
}

bool isConsoleFileHandle(HANDLE handle) {
	auto file = getValidFileHandle(handle);
	// Console probe APIs must fail for redirected pipes/files.  Old Cygwin
	// uses these failures to choose its POSIX pipe/file fhandlers for stdio.
	return file && isatty(file->fd);
}

} // namespace

namespace kernel32 {

BOOL WINAPI GetConsoleMode(HANDLE hConsoleHandle, LPDWORD lpMode) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetConsoleMode(%p, %p)\n", hConsoleHandle, lpMode);
	if (!isConsoleFileHandle(hConsoleHandle)) {
		setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	if (lpMode) {
		*lpMode = 0;
	}
	return TRUE;
}

BOOL WINAPI SetConsoleMode(HANDLE hConsoleHandle, DWORD dwMode) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetConsoleMode(%p, 0x%x)\n", hConsoleHandle, dwMode);
	(void)dwMode;
	if (!isConsoleFileHandle(hConsoleHandle)) {
		setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	return TRUE;
}

UINT WINAPI GetConsoleCP() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: GetConsoleCP() -> 65001\n");
	return 65001; // UTF-8
}

UINT WINAPI GetConsoleOutputCP() {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: GetConsoleOutputCP() -> 65001\n");
	return 65001; // UTF-8
}

BOOL WINAPI SetConsoleCtrlHandler(PHANDLER_ROUTINE HandlerRoutine, BOOL Add) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: SetConsoleCtrlHandler(%p, %u)\n", reinterpret_cast<const void *>(HandlerRoutine), Add);
	(void)HandlerRoutine;
	(void)Add;
	return TRUE;
}

BOOL WINAPI GetConsoleScreenBufferInfo(HANDLE hConsoleOutput, CONSOLE_SCREEN_BUFFER_INFO *lpConsoleScreenBufferInfo) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetConsoleScreenBufferInfo(%p, %p)\n", hConsoleOutput, lpConsoleScreenBufferInfo);
	if (!isConsoleFileHandle(hConsoleOutput)) {
		setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
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

BOOL WINAPI SetConsoleCursorPosition(HANDLE hConsoleOutput, COORD dwCursorPosition) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SetConsoleCursorPosition(%p, {%d, %d})\n", hConsoleOutput, dwCursorPosition.X, dwCursorPosition.Y);
	auto file = wibo::handles().getAs<FileObject>(hConsoleOutput);
	if (!file || !file->valid()) {
		setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	if (dwCursorPosition.X == 0 && dwCursorPosition.Y > 0) {
		// Old Cygwin console output advances lines by moving the cursor
		// instead of writing newline bytes. Preserve that when the console
		// handle is really backed by a host stream or redirected file.
		const char newline = '\n';
		auto io = files::write(file.get(), &newline, sizeof(newline), std::nullopt, true);
		if (io.unixError != 0) {
			setLastError(wibo::winErrorFromErrno(io.unixError));
			return FALSE;
		}
	}
	return TRUE;
}

BOOL WINAPI WriteConsoleW(HANDLE hConsoleOutput, LPCWSTR lpBuffer, DWORD nNumberOfCharsToWrite,
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
	if (!file || !file->valid()) {
		setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	if (file->fd == STDOUT_FILENO || file->fd == STDERR_FILENO) {
		auto str = wideStringToString(lpBuffer, static_cast<int>(nNumberOfCharsToWrite));
		auto io = files::write(file.get(), str.c_str(), str.size(), std::nullopt, true);
		if (lpNumberOfCharsWritten) {
			*lpNumberOfCharsWritten = io.bytesTransferred;
		}
		if (io.unixError != 0) {
			setLastError(wibo::winErrorFromErrno(io.unixError));
			return FALSE;
		}
		return TRUE;
	}

	setLastError(ERROR_INVALID_HANDLE);
	return FALSE;
}

BOOL WINAPI GetNumberOfConsoleInputEvents(HANDLE hConsoleInput, LPDWORD lpNumberOfEvents) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetNumberOfConsoleInputEvents(%p, %p)\n", hConsoleInput, lpNumberOfEvents);
	if (!isConsoleFileHandle(hConsoleInput)) {
		setLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	if (!lpNumberOfEvents) {
		setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	*lpNumberOfEvents = 0;
	return TRUE;
}

DWORD WINAPI GetConsoleTitleA(LPSTR lpConsoleTitle, DWORD nSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetConsoleTitleA(%p, %u)\n", lpConsoleTitle, nSize);
	if (lpConsoleTitle && nSize > 0) {
		lpConsoleTitle[0] = '\0';
	}
	setLastError(ERROR_SUCCESS);
	return 0;
}

DWORD WINAPI GetConsoleTitleW(LPWSTR lpConsoleTitle, DWORD nSize) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("GetConsoleTitleW(%p, %u)\n", lpConsoleTitle, nSize);
	if (lpConsoleTitle && nSize > 0) {
		lpConsoleTitle[0] = 0;
	}
	setLastError(ERROR_SUCCESS);
	return 0;
}

BOOL WINAPI PeekConsoleInputA(HANDLE hConsoleInput, INPUT_RECORD *lpBuffer, DWORD nLength,
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

BOOL WINAPI ReadConsoleInputA(HANDLE hConsoleInput, INPUT_RECORD *lpBuffer, DWORD nLength,
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

BOOL WINAPI VerifyConsoleIoHandle(HANDLE handle) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("STUB: VerifyConsoleIoHandle(%p)\n", handle);
	(void)handle;
	return FALSE;
}

} // namespace kernel32
