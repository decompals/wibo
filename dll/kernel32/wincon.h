#pragma once

#include "common.h"

struct COORD {
	SHORT X;
	SHORT Y;
};

struct SMALL_RECT {
	SHORT Left;
	SHORT Top;
	SHORT Right;
	SHORT Bottom;
};

struct CONSOLE_SCREEN_BUFFER_INFO {
	COORD dwSize;
	COORD dwCursorPosition;
	WORD wAttributes;
	SMALL_RECT srWindow;
	COORD dwMaximumWindowSize;
};

struct INPUT_RECORD;

using PHANDLER_ROUTINE = BOOL(WIN_FUNC *)(DWORD CtrlType);

namespace kernel32 {

BOOL WIN_FUNC GetConsoleMode(HANDLE hConsoleHandle, LPDWORD lpMode);
BOOL WIN_FUNC SetConsoleMode(HANDLE hConsoleHandle, DWORD dwMode);
UINT WIN_FUNC GetConsoleCP();
UINT WIN_FUNC GetConsoleOutputCP();
BOOL WIN_FUNC SetConsoleCtrlHandler(PHANDLER_ROUTINE HandlerRoutine, BOOL Add);
BOOL WIN_FUNC GetConsoleScreenBufferInfo(HANDLE hConsoleOutput, CONSOLE_SCREEN_BUFFER_INFO *lpConsoleScreenBufferInfo);
BOOL WIN_FUNC WriteConsoleW(HANDLE hConsoleOutput, LPCVOID lpBuffer, DWORD nNumberOfCharsToWrite,
							LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved);
DWORD WIN_FUNC GetConsoleTitleA(LPSTR lpConsoleTitle, DWORD nSize);
DWORD WIN_FUNC GetConsoleTitleW(LPWSTR lpConsoleTitle, DWORD nSize);
BOOL WIN_FUNC PeekConsoleInputA(HANDLE hConsoleInput, INPUT_RECORD *lpBuffer, DWORD nLength,
								LPDWORD lpNumberOfEventsRead);
BOOL WIN_FUNC ReadConsoleInputA(HANDLE hConsoleInput, INPUT_RECORD *lpBuffer, DWORD nLength,
								LPDWORD lpNumberOfEventsRead);

} // namespace kernel32
