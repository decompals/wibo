#include "common.h"
#include <algorithm>
#include <ctype.h>
#include <filesystem>
#include <string>

namespace kernel32 {
	uint32_t WIN_FUNC GetLastError() {
		return wibo::lastError;
	}

	void *WIN_FUNC GetCurrentProcess() {
		return (void *) 0xFFFFFFFF;
	}

	void WIN_FUNC InitializeCriticalSection(void *param) {
		// printf("InitializeCriticalSection(...)\n");
	}
	void WIN_FUNC DeleteCriticalSection(void *param) {
		// printf("DeleteCriticalSection(...)\n");
	}
	void WIN_FUNC EnterCriticalSection(void *param) {
		// printf("EnterCriticalSection(...)\n");
	}
	void WIN_FUNC LeaveCriticalSection(void *param) {
		// printf("LeaveCriticalSection(...)\n");
	}

	/*
	 * TLS (Thread-Local Storage)
	 */
	enum { MAX_TLS_VALUES = 100 };
	static bool tlsValuesUsed[MAX_TLS_VALUES] = { false };
	static void *tlsValues[MAX_TLS_VALUES];
	unsigned int WIN_FUNC TlsAlloc() {
		printf("TlsAlloc()\n");
		for (int i = 0; i < MAX_TLS_VALUES; i++) {
			if (tlsValuesUsed[i] == false) {
				tlsValuesUsed[i] = true;
				tlsValues[i] = 0;
				printf("...returning %d\n", i);
				return i;
			}
		}
		printf("...returning nothing\n");
		return 0xFFFFFFFF;
	}
	unsigned int WIN_FUNC TlsFree(unsigned int dwTlsIndex) {
		printf("TlsFree(%u)\n", dwTlsIndex);
		if (dwTlsIndex >= 0 && dwTlsIndex < MAX_TLS_VALUES && tlsValuesUsed[dwTlsIndex]) {
			tlsValuesUsed[dwTlsIndex] = false;
			return 1;
		} else {
			return 0;
		}
	}
	void *WIN_FUNC TlsGetValue(unsigned int dwTlsIndex) {
		// printf("TlsGetValue(%u)\n", dwTlsIndex);
		if (dwTlsIndex >= 0 && dwTlsIndex < MAX_TLS_VALUES && tlsValuesUsed[dwTlsIndex])
			return tlsValues[dwTlsIndex];
		else
			return 0;
	}
	unsigned int WIN_FUNC TlsSetValue(unsigned int dwTlsIndex, void *lpTlsValue) {
		// printf("TlsSetValue(%u, %p)\n", dwTlsIndex, lpTlsValue);
		if (dwTlsIndex >= 0 && dwTlsIndex < MAX_TLS_VALUES && tlsValuesUsed[dwTlsIndex]) {
			tlsValues[dwTlsIndex] = lpTlsValue;
			return 1;
		} else {
			return 0;
		}
	}

	/*
	 * Memory
	 */
	void *WIN_FUNC GlobalAlloc(uint32_t uFlags, size_t dwBytes) {
		printf("GlobalAlloc(flags=%x, size=%x)\n", uFlags, dwBytes);
		if (uFlags & 2) {
			// GMEM_MOVEABLE - not implemented rn
			return 0;
		} else {
			// GMEM_FIXED - this is simpler
			void *buffer = malloc(dwBytes);
			if (buffer && (uFlags & 0x40)) {
				// GMEM_ZEROINT
				memset(buffer, 0, dwBytes);
			}
			return buffer;
		}
	}
	void *WIN_FUNC GlobalFree(void *hMem) {
		free(hMem);
		return 0;
	}

	/*
	 * Environment
	 */
	char *WIN_FUNC GetCommandLineA() {
		return wibo::commandLine;
	}

	char *WIN_FUNC GetEnvironmentStrings() {
		// Step 1, figure out the size of the buffer we need.
		size_t bufSize = 0;
		char **work = environ;

		while (*work) {
			bufSize += strlen(*work) + 1;
			work++;
		}
		bufSize++;

		// Step 2, actually build that buffer
		char *buffer = (char *) malloc(bufSize);
		char *ptr = buffer;
		work = environ;

		while (*work) {
			size_t strSize = strlen(*work);
			memcpy(ptr, *work, strSize);
			ptr[strSize] = 0;
			ptr += strSize + 1;
			work++;
		}
		*ptr = 0; // an extra null at the end

		return buffer;
	}

	void WIN_FUNC FreeEnvironmentStringsA(char *buffer) {
		free(buffer);
	}

	/*
	 * I/O
	 */
	void *WIN_FUNC GetStdHandle(uint32_t nStdHandle) {
		switch (nStdHandle) {
			case ((uint32_t) -10): // STD_INPUT_HANDLE
				return stdin;
			case ((uint32_t) -11): // STD_OUTPUT_HANDLE
				return stdout;
			case ((uint32_t) -12): // STD_ERROR_HANDLE
				return stderr;
			default:
				return (void *) 0xFFFFFFFF;
		}
	}

	unsigned int WIN_FUNC DuplicateHandle(void *hSourceProcessHandle, void *hSourceHandle, void *hTargetProcessHandle, void **lpTargetHandle, unsigned int dwDesiredAccess, unsigned int bInheritHandle, unsigned int dwOptions) {
		// This is kinda silly...
		if (hSourceHandle == stdin || hSourceHandle == stdout || hSourceHandle == stderr) {
			// Just pretend we duplicated it, why not
			*lpTargetHandle = hSourceHandle;
			return 1;
		}

		// This probably won't come up
		printf("Unhandled DuplicateHandle(source=%p)\n", hSourceHandle);
		return 0;
	}

	std::filesystem::path pathFromWindows(const char *inStr) {
		// Convert to forward slashes
		std::string str = inStr;
		std::replace(str.begin(), str.end(), '\\', '/');

		// Remove the drive letter
		if (str.starts_with("c:/") || str.starts_with("C:/")) {
			str.erase(0, 2);
		}

		return std::filesystem::path(str);
	}

	std::string pathToWindows(const std::filesystem::path &path) {
		std::string str = path;

		if (path.is_absolute()) {
			str.insert(0, "C:");
		}

		std::replace(str.begin(), str.end(), '/', '\\');
		return str;
	}

	unsigned int WIN_FUNC GetFullPathNameA(const char *lpFileName, unsigned int nBufferLength, char *lpBuffer, char **lpFilePart) {
		printf("GetFullPathNameA(%s)...\n", lpFileName);
		std::filesystem::path absPath = std::filesystem::absolute(pathFromWindows(lpFileName));
		std::string absStr = pathToWindows(absPath);
		printf("AbsPath: %s - %s\n", absPath.c_str(), absStr.c_str());

		// Enough space?
		if ((absStr.size() + 1) <= nBufferLength) {
			strcpy(lpBuffer, absStr.c_str());

			// Do we need to fill in FilePart?
			if (lpFilePart) {
				*lpFilePart = 0;
				if (!std::filesystem::is_directory(absPath)) {
					*lpFilePart = strrchr(lpBuffer, '\\');
					if (*lpFilePart)
						*lpFilePart += 1;
				}
			}

			return absStr.size();
		} else {
			return absStr.size() + 1;
		}
	}

	unsigned int WIN_FUNC GetFileAttributesA(const char *lpFileName) {
		auto path = pathFromWindows(lpFileName);
		printf("GetFileAttributesA(%s)... (%s)\n", lpFileName, path.c_str());
		auto status = std::filesystem::status(path);

		wibo::lastError = 0;

		switch (status.type()) {
			case std::filesystem::file_type::regular:
				printf("File exists\n");
				return 0x80; // FILE_ATTRIBUTE_NORMAL
			case std::filesystem::file_type::directory:
				return 0x10; // FILE_ATTRIBUTE_DIRECTORY
			case std::filesystem::file_type::not_found:
			default:
				printf("File does not exist\n");
				wibo::lastError = 2; // ERROR_FILE_NOT_FOUND
				return 0xFFFFFFFF; // INVALID_FILE_ATTRIBUTES
		}
	}

	unsigned int WIN_FUNC WriteFile(void *hFile, const void *lpBuffer, unsigned int nNumberOfBytesToWrite, unsigned int *lpNumberOfBytesWritten, void *lpOverlapped) {
		// for now, we VERY naively assume that the handle is a FILE*
		// haha this is gonna come back and bite me, isn't it
		wibo::lastError = 0;

		size_t written = fwrite(lpBuffer, 1, nNumberOfBytesToWrite, (FILE *) hFile);
		if (lpNumberOfBytesWritten)
			*lpNumberOfBytesWritten = written;

		if (written == 0)
			wibo::lastError = 29; // ERROR_WRITE_FAULT

		return (written == nNumberOfBytesToWrite);
	}

	/*
	 * Console Nonsense
	 */
	unsigned int WIN_FUNC SetConsoleCtrlHandler(void *HandlerRoutine, unsigned int Add) {
		// This is a function that gets called when doing ^C
		// We might want to call this later (being mindful that it'll be stdcall I think)

		// For now, just pretend we did the thing
		return 1;
	}

	struct CONSOLE_SCREEN_BUFFER_INFO {
		int16_t dwSize_x;
		int16_t dwSize_y;
		int16_t dwCursorPosition_x;
		int16_t dwCursorPosition_y;
		uint16_t wAttributes;
		int16_t srWindow_left;
		int16_t srWindow_top;
		int16_t srWindow_right;
		int16_t srWindow_bottom;
		int16_t dwMaximumWindowSize_x;
		int16_t dwMaximumWindowSize_y;
	};

	unsigned int WIN_FUNC GetConsoleScreenBufferInfo(void *hConsoleOutput, CONSOLE_SCREEN_BUFFER_INFO *lpConsoleScreenBufferInfo) {
		// Tell a lie
		// mwcc doesn't care about anything else
		lpConsoleScreenBufferInfo->dwSize_x = 80;
		lpConsoleScreenBufferInfo->dwSize_y = 25;

		return 1;
	}

	unsigned int WIN_FUNC GetSystemDirectoryA(char *lpBuffer, unsigned int uSize) {
		strcpy(lpBuffer, "C:\\Windows\\System32");
		return strlen(lpBuffer);
	}

	unsigned int WIN_FUNC GetWindowsDirectoryA(char *lpBuffer, unsigned int uSize) {
		strcpy(lpBuffer, "C:\\Windows");
		return strlen(lpBuffer);
	}
}

void *wibo::resolveKernel32(const char *name) {
	if (strcmp(name, "GetLastError") == 0) return (void *) kernel32::GetLastError;
	if (strcmp(name, "GetCurrentProcess") == 0) return (void *) kernel32::GetCurrentProcess;
	if (strcmp(name, "InitializeCriticalSection") == 0) return (void *) kernel32::InitializeCriticalSection;
	if (strcmp(name, "DeleteCriticalSection") == 0) return (void *) kernel32::DeleteCriticalSection;
	if (strcmp(name, "EnterCriticalSection") == 0) return (void *) kernel32::EnterCriticalSection;
	if (strcmp(name, "LeaveCriticalSection") == 0) return (void *) kernel32::LeaveCriticalSection;
	if (strcmp(name, "GlobalAlloc") == 0) return (void *) kernel32::GlobalAlloc;
	if (strcmp(name, "GlobalFree") == 0) return (void *) kernel32::GlobalFree;
	if (strcmp(name, "TlsAlloc") == 0) return (void *) kernel32::TlsAlloc;
	if (strcmp(name, "TlsFree") == 0) return (void *) kernel32::TlsFree;
	if (strcmp(name, "TlsGetValue") == 0) return (void *) kernel32::TlsGetValue;
	if (strcmp(name, "TlsSetValue") == 0) return (void *) kernel32::TlsSetValue;
	if (strcmp(name, "GetCommandLineA") == 0) return (void *) kernel32::GetCommandLineA;
	if (strcmp(name, "GetEnvironmentStrings") == 0) return (void *) kernel32::GetEnvironmentStrings;
	if (strcmp(name, "FreeEnvironmentStringsA") == 0) return (void *) kernel32::FreeEnvironmentStringsA;
	if (strcmp(name, "GetStdHandle") == 0) return (void *) kernel32::GetStdHandle;
	if (strcmp(name, "DuplicateHandle") == 0) return (void *) kernel32::DuplicateHandle;
	if (strcmp(name, "GetFullPathNameA") == 0) return (void *) kernel32::GetFullPathNameA;
	if (strcmp(name, "GetFileAttributesA") == 0) return (void *) kernel32::GetFileAttributesA;
	if (strcmp(name, "WriteFile") == 0) return (void *) kernel32::WriteFile;
	if (strcmp(name, "SetConsoleCtrlHandler") == 0) return (void *) kernel32::SetConsoleCtrlHandler;
	if (strcmp(name, "GetConsoleScreenBufferInfo") == 0) return (void *) kernel32::GetConsoleScreenBufferInfo;
	if (strcmp(name, "GetSystemDirectoryA") == 0) return (void *) kernel32::GetSystemDirectoryA;
	if (strcmp(name, "GetWindowsDirectoryA") == 0) return (void *) kernel32::GetWindowsDirectoryA;
	return 0;
}
