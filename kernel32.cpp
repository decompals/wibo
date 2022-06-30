#include "common.h"
#include <algorithm>
#include <ctype.h>
#include <filesystem>
#include <string>
#include <malloc.h>

namespace kernel32 {

	uint32_t WIN_FUNC GetLastError() {
		return wibo::lastError;
	}

	void *WIN_FUNC GetCurrentProcess() {
		return (void *) 0xFFFFFFFF;
	}

	void WIN_FUNC ExitProcess(unsigned int uExitCode) {
		exit(uExitCode);
	}

	int WIN_FUNC CreateProcessA(
		const char *lpApplicationName,
		char *lpCommandLine,
		void *lpProcessAttributes,
		void *lpThreadAttributes,
		int bInheritHandles,
		int dwCreationFlags,
		void *lpEnvironment,
		const char *lpCurrentDirectory,
		void *lpStartupInfo,
		void *lpProcessInformation
	) {
		printf("CreateProcessA %s \"%s\" %p %p %d 0x%x %p %s %p %p\n",
			lpApplicationName,
			lpCommandLine,
			lpProcessAttributes,
			lpThreadAttributes,
			bInheritHandles,
			dwCreationFlags,
			lpEnvironment,
			lpCurrentDirectory ? lpCurrentDirectory : "<none>",
			lpStartupInfo,
			lpProcessInformation
		);
		printf("Cannot handle process creation, aborting\n");
		exit(1);
		return 0;
	}

	int WIN_FUNC GetSystemDefaultLangID() {
		return 0;
	}

	void WIN_FUNC InitializeCriticalSection(void *param) {
		// DEBUG_LOG("InitializeCriticalSection(...)\n");
	}
	void WIN_FUNC DeleteCriticalSection(void *param) {
		// DEBUG_LOG("DeleteCriticalSection(...)\n");
	}
	void WIN_FUNC EnterCriticalSection(void *param) {
		// DEBUG_LOG("EnterCriticalSection(...)\n");
	}
	void WIN_FUNC LeaveCriticalSection(void *param) {
		// DEBUG_LOG("LeaveCriticalSection(...)\n");
	}

	/*
	 * TLS (Thread-Local Storage)
	 */
	enum { MAX_TLS_VALUES = 100 };
	static bool tlsValuesUsed[MAX_TLS_VALUES] = { false };
	static void *tlsValues[MAX_TLS_VALUES];
	unsigned int WIN_FUNC TlsAlloc() {
		DEBUG_LOG("TlsAlloc()\n");
		for (size_t i = 0; i < MAX_TLS_VALUES; i++) {
			if (tlsValuesUsed[i] == false) {
				tlsValuesUsed[i] = true;
				tlsValues[i] = 0;
				DEBUG_LOG("...returning %d\n", i);
				return i;
			}
		}
		DEBUG_LOG("...returning nothing\n");
		return 0xFFFFFFFF;
	}
	unsigned int WIN_FUNC TlsFree(unsigned int dwTlsIndex) {
		DEBUG_LOG("TlsFree(%u)\n", dwTlsIndex);
		if (dwTlsIndex >= 0 && dwTlsIndex < MAX_TLS_VALUES && tlsValuesUsed[dwTlsIndex]) {
			tlsValuesUsed[dwTlsIndex] = false;
			return 1;
		} else {
			return 0;
		}
	}
	void *WIN_FUNC TlsGetValue(unsigned int dwTlsIndex) {
		// DEBUG_LOG("TlsGetValue(%u)\n", dwTlsIndex);
		if (dwTlsIndex >= 0 && dwTlsIndex < MAX_TLS_VALUES && tlsValuesUsed[dwTlsIndex])
			return tlsValues[dwTlsIndex];
		else
			return 0;
	}
	unsigned int WIN_FUNC TlsSetValue(unsigned int dwTlsIndex, void *lpTlsValue) {
		// DEBUG_LOG("TlsSetValue(%u, %p)\n", dwTlsIndex, lpTlsValue);
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
		// DEBUG_LOG("GlobalAlloc(flags=%x, size=%x)\n", uFlags, dwBytes);
		if (uFlags & 2) {
			// GMEM_MOVEABLE - not implemented rn
			assert(0);
			return 0;
		} else {
			// GMEM_FIXED - this is simpler
			if (dwBytes == 0)
				dwBytes = 1;
			assert(dwBytes > 0);
			void *buffer = malloc(dwBytes);
			if (buffer && (uFlags & 0x40)) {
				// GMEM_ZEROINT
				memset(buffer, 0, malloc_usable_size(buffer));
			}
			return buffer;
		}
	}
	void *WIN_FUNC GlobalFree(void *hMem) {
		free(hMem);
		return 0;
	}

	void *WIN_FUNC GlobalReAlloc(void *hMem, size_t dwBytes, uint32_t uFlags) {
		if (uFlags & 0x80) { // GMEM_MODIFY
			assert(0);
		} else {
			if (dwBytes == 0)
				dwBytes = 1;
			size_t oldSize = malloc_usable_size(hMem);
			void *buffer = realloc(hMem, dwBytes);
			size_t newSize = malloc_usable_size(buffer);
			if (buffer && (uFlags & 0x40) && newSize > oldSize) {
				// GMEM_ZEROINT
				memset((char*)buffer + oldSize, 0, newSize - oldSize);
			}
			return buffer;
		}
	}

	unsigned int WIN_FUNC GlobalFlags(void *hMem) {
		return 0;
	}

	/*
	 * Environment
	 */
	char *WIN_FUNC GetCommandLineA() {
		return wibo::commandLine;
	}

	char *WIN_FUNC GetEnvironmentStrings() {
		DEBUG_LOG("GetEnvironmentStrings\n");
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

	uint16_t* WIN_FUNC GetEnvironmentStringsW() {
		DEBUG_LOG("GetEnvironmentStringsW\n");
		// Step 1, figure out the size of the buffer we need.
		size_t bufSizeW = 0;
		char **work = environ;

		while (*work) {
			// "hello|" -> " h e l l o|"
			bufSizeW += strlen(*work) + 1;
			work++;
		}
		bufSizeW++;

		// Step 2, actually build that buffer
		uint16_t *buffer = (uint16_t *) malloc(bufSizeW * 2);
		uint16_t *ptr = buffer;
		work = environ;

		while (*work) {
			size_t strSize = strlen(*work);
			for (size_t i = 0; i < strSize; i++) {
				*ptr++ = (*work)[i];
			}
			*ptr++ = 0; // NUL terminate
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
		DEBUG_LOG("Unhandled DuplicateHandle(source=%p)\n", hSourceHandle);
		return 0;
	}

	int WIN_FUNC CloseHandle(void *hObject) {
		// we *probably* won't run out of file descriptors even if we never close files
		DEBUG_LOG("CloseHandle\n");
		return 1;
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
		DEBUG_LOG("GetFullPathNameA(%s)...\n", lpFileName);
		std::filesystem::path absPath = std::filesystem::absolute(pathFromWindows(lpFileName));
		std::string absStr = pathToWindows(absPath);
		DEBUG_LOG("AbsPath: %s - %s\n", absPath.c_str(), absStr.c_str());

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

	void *WIN_FUNC FindFirstFileA(const char *lpFileName, void *lpFindFileData) {
		auto path = pathFromWindows(lpFileName);
		DEBUG_LOG("FindFirstFileA %s (%s)\n", lpFileName, path.c_str());
		wibo::lastError = 2; // ERROR_FILE_NOT_FOUND
		return (void *) 0xFFFFFFFF;
	}

	unsigned int WIN_FUNC GetFileAttributesA(const char *lpFileName) {
		auto path = pathFromWindows(lpFileName);
		DEBUG_LOG("GetFileAttributesA(%s)... (%s)\n", lpFileName, path.c_str());
		auto status = std::filesystem::status(path);

		wibo::lastError = 0;

		switch (status.type()) {
			case std::filesystem::file_type::regular:
				DEBUG_LOG("File exists\n");
				return 0x80; // FILE_ATTRIBUTE_NORMAL
			case std::filesystem::file_type::directory:
				return 0x10; // FILE_ATTRIBUTE_DIRECTORY
			case std::filesystem::file_type::not_found:
			default:
				DEBUG_LOG("File does not exist\n");
				wibo::lastError = 2; // ERROR_FILE_NOT_FOUND
				return 0xFFFFFFFF; // INVALID_FILE_ATTRIBUTES
		}
	}

	unsigned int WIN_FUNC WriteFile(void *hFile, const void *lpBuffer, unsigned int nNumberOfBytesToWrite, unsigned int *lpNumberOfBytesWritten, void *lpOverlapped) {
		DEBUG_LOG("WriteFile %d\n", nNumberOfBytesToWrite);
		assert(!lpOverlapped);
		// for now, we VERY naively assume that the handle is a FILE*
		// haha this is gonna come back and bite me, isn't it
		wibo::lastError = 0;

		size_t written = fwrite(lpBuffer, 1, nNumberOfBytesToWrite, (FILE *) hFile);
		if (lpNumberOfBytesWritten)
			*lpNumberOfBytesWritten = written;

#if 0
		printf("writing:\n");
		for (unsigned int i = 0; i < nNumberOfBytesToWrite; i++) {
			printf("%c", ((const char*)lpBuffer)[i]);
		}
		printf("\n");
#endif

		if (written == 0)
			wibo::lastError = 29; // ERROR_WRITE_FAULT

		return (written == nNumberOfBytesToWrite);
	}

	unsigned int WIN_FUNC ReadFile(void *hFile, void *lpBuffer, unsigned int nNumberOfBytesToRead, unsigned int *lpNumberOfBytesRead, void *lpOverlapped) {
		DEBUG_LOG("ReadFile %d\n", nNumberOfBytesToRead);
		assert(!lpOverlapped);
		wibo::lastError = 0;

		size_t read = fread(lpBuffer, 1, nNumberOfBytesToRead, (FILE *) hFile);
		*lpNumberOfBytesRead = read;
		return 1;
	}

	void *WIN_FUNC CreateFileA(
			const char* lpFileName,
			unsigned int dwDesiredAccess,
			unsigned int dwShareMode,
			void *lpSecurityAttributes,
			unsigned int dwCreationDisposition,
			unsigned int dwFlagsAndAttributes,
			void *hTemplateFile) {
		std::string path = pathFromWindows(lpFileName);
		DEBUG_LOG("CreateFileA(filename=%s (%s), desiredAccess=0x%x, shareMode=%u, securityAttributes=%p, creationDisposition=%u, flagsAndAttributes=%u)\n",
				lpFileName, path.c_str(),
				dwDesiredAccess, dwShareMode, lpSecurityAttributes,
				dwCreationDisposition, dwFlagsAndAttributes);
		wibo::lastError = 0;
		if (dwDesiredAccess == 0x80000000) { // read
			return fopen(path.c_str(), "rb");
		}
		if (dwDesiredAccess == 0x40000000) { // write
			return fopen(path.c_str(), "wb");
		}
		if (dwDesiredAccess == 0xc0000000) { // read/write
			return fopen(path.c_str(), "wb+");
		}
		assert(0);
		return 0;
	}

	int WIN_FUNC DeleteFileA(const char* lpFileName) {
		std::string path = pathFromWindows(lpFileName);
		DEBUG_LOG("DeleteFileA %s (%s)\n", lpFileName, path.c_str());
		unlink(path.c_str());
		return 1;
	}

	unsigned int WIN_FUNC SetFilePointer(void *hFile, int lDistanceToMove, int *lpDistanceToMoveHigh, int dwMoveMethod) {
		DEBUG_LOG("SetFilePointer %d %d %d\n", lDistanceToMove, (lpDistanceToMoveHigh ? *lpDistanceToMoveHigh : -1), dwMoveMethod);
		assert(!lpDistanceToMoveHigh);
		FILE *fp = (FILE*) hFile;
		int r = fseek(fp, lDistanceToMove,
				dwMoveMethod == 0 ? SEEK_SET :
				dwMoveMethod == 1 ? SEEK_CUR :
				SEEK_END);
		assert(r >= 0);
		r = ftell(fp);
		assert(r >= 0);
		return r;
	}

	/*
	 * Time
	 */
	unsigned int WIN_FUNC GetFileSize(void *hFile, unsigned int *lpFileSizeHigh) {
		DEBUG_LOG("GetFileSize\n");
		FILE *fp = (FILE*)hFile;
		long pos = ftell(fp);
		assert(pos >= 0);
		int r = fseek(fp, 0L, SEEK_END);
		assert(r == 0);
		long sz = ftell(fp);
		assert(sz >= 0);
		fseek(fp, pos, SEEK_SET);
		if (lpFileSizeHigh) {
			*lpFileSizeHigh = 0;
		}
		DEBUG_LOG("-> %d\n", (int)sz);
		return (unsigned int)sz;
	}

	struct FILETIME {
		unsigned int dwLowDateTime;
		unsigned int dwHighDateTime;
	};

	int WIN_FUNC GetFileTime(void *hFile, FILETIME *lpCreationTime, FILETIME *lpLastAccessTime, FILETIME *lpLastWriteTime) {
		DEBUG_LOG("GetFileTime %p %p %p\n", lpCreationTime, lpLastAccessTime, lpLastWriteTime);
		if (lpCreationTime) lpCreationTime->dwLowDateTime = lpCreationTime->dwHighDateTime = 0;
		if (lpLastAccessTime) lpLastAccessTime->dwLowDateTime = lpLastAccessTime->dwHighDateTime = 0;
		if (lpLastWriteTime) lpLastWriteTime->dwLowDateTime = lpLastWriteTime->dwHighDateTime = 0;
		return 1;
	}

	struct SYSTEMTIME {
		short wYear;
		short wMonth;
		short wDayOfWeek;
		short wDay;
		short wHour;
		short wMinute;
		short wSecond;
		short wMilliseconds;
	};

	void WIN_FUNC GetSystemTime(SYSTEMTIME *lpSystemTime) {
		DEBUG_LOG("GetSystemTime\n");
		lpSystemTime->wYear = 0;
		lpSystemTime->wMonth = 0;
		lpSystemTime->wDayOfWeek = 0;
		lpSystemTime->wDay = 0;
		lpSystemTime->wHour = 0;
		lpSystemTime->wMinute = 0;
		lpSystemTime->wSecond = 0;
		lpSystemTime->wMilliseconds = 0;
	}

	void WIN_FUNC GetLocalTime(SYSTEMTIME *lpSystemTime) {
		DEBUG_LOG("GetLocalTime\n");
		GetSystemTime(lpSystemTime);
	}

	int WIN_FUNC SystemTimeToFileTime(const SYSTEMTIME *lpSystemTime, FILETIME *lpFileTime) {
		DEBUG_LOG("SystemTimeToFileTime\n");
		lpFileTime->dwLowDateTime = 0;
		lpFileTime->dwHighDateTime = 0;
		return 1;
	}

	int WIN_FUNC GetTickCount() {
		DEBUG_LOG("GetTickCount\n");
		return 0;
	}

	struct TIME_ZONE_INFORMATION {
		int Bias;
		short StandardName[32];
		SYSTEMTIME StandardDate;
		int StandardBias;
		short DaylightName[32];
		SYSTEMTIME DaylightDate;
		int DaylightBias;
	};

	int WIN_FUNC GetTimeZoneInformation(TIME_ZONE_INFORMATION *lpTimeZoneInformation) {
		memset(lpTimeZoneInformation, 0, sizeof(*lpTimeZoneInformation));
		return 0;
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

	unsigned int WIN_FUNC GetCurrentDirectoryA(unsigned int uSize, char *lpBuffer) {
        DEBUG_LOG("GetCurrentDirectoryA\n");

        std::filesystem::path cwd = std::filesystem::current_path();
		std::string path = pathToWindows(cwd);

		assert(path.size() < uSize);

        strcpy(lpBuffer, path.c_str());
        return path.size();
    }

	void* WIN_FUNC GetModuleHandleA(const char* lpModuleName) {
		DEBUG_LOG("GetModuleHandleA %s\n", lpModuleName);
		// wibo::lastError = 0;
		return (void*)1;
	}

	unsigned int WIN_FUNC GetModuleFileNameA(void* hModule, char* lpFilename, unsigned int nSize) {
		DEBUG_LOG("GetModuleFileNameA %p (%s)\n", hModule, lpFilename);
		wibo::lastError = 0;
		return 0;
	}

	void* WIN_FUNC FindResourceA(void* hModule, const char* lpName, const char* lpType) {
		DEBUG_LOG("FindResourceA %p %s %s\n", hModule, lpName, lpType);
		return (void*)2;
	}

	void* WIN_FUNC LoadResource(void* hModule, void* res) {
		DEBUG_LOG("LoadResource %p %p\n", hModule, res);
		return (void*)3;
	}

	void* WIN_FUNC LockResource(void* res) {
		DEBUG_LOG("LockResource %p\n", res);
		return (void*)4;
	}

	unsigned int WIN_FUNC SizeofResource(void* hModule, void* res) {
		DEBUG_LOG("SizeofResource %p %p\n", hModule, res);
		return 0;
	}

	void* WIN_FUNC LoadLibraryA(const char* lpLibFileName) {
		DEBUG_LOG("LoadLibraryA %s\n", lpLibFileName);
		return (void*)5;
	}

	int WIN_FUNC FreeLibrary(void* hLibModule) {
		DEBUG_LOG("FreeLibrary %p\n", hLibModule);
		return 1;
	}

	int WIN_FUNC GetVersion() {
		DEBUG_LOG("GetVersion\n");
		return 1;
	}

	void *WIN_FUNC HeapCreate(unsigned int flOptions, unsigned int dwInitialSize, unsigned int dwMaximumSize) {
		DEBUG_LOG("HeapCreate %u %u %u\n", flOptions, dwInitialSize, dwMaximumSize);
		if (flOptions & 0x00000001) {
			// HEAP_NO_SERIALIZE
		}
		if (flOptions & 0x00040000) {
			// HEAP_CREATE_ENABLE_EXECUTE
		}
		if (flOptions & 0x00000004) {
			// HEAP_GENERATE_EXCEPTIONS
		}

		// return a dummy value
		wibo::lastError = 0;
		return (void *) 0x12345678;
	}

	void *WIN_FUNC VirtualAlloc(void *lpAddress, unsigned int dwSize, unsigned int flAllocationType, unsigned int flProtect) {
		DEBUG_LOG("VirtualAlloc %p %u %u %u\n",lpAddress, dwSize, flAllocationType, flProtect);
		if (flAllocationType & 0x2000) { // MEM_RESERVE
			// do this for now...
			assert(lpAddress == NULL);
			void *mem = 0;
			posix_memalign(&mem, 0x1000, dwSize);
			DEBUG_LOG("VirtualAlloc returning %p\n", mem);
			return mem;
		} else {
			assert(lpAddress != NULL);
			return lpAddress;
		}
	}

	typedef struct _STARTUPINFOA {
		unsigned int   cb;
	    char          *lpReserved;
	    char          *lpDesktop;
	    char          *lpTitle;
	    unsigned int   dwX;
	    unsigned int   dwY;
	    unsigned int   dwXSize;
	    unsigned int   dwYSize;
	    unsigned int   dwXCountChars;
	    unsigned int   dwYCountChars;
	    unsigned int   dwFillAttribute;
	    unsigned int   dwFlags;
	    unsigned short wShowWindow;
	    unsigned short cbReserved2;
	    unsigned char  lpReserved2;
	    void          *hStdInput;
	    void          *hStdOutput;
	    void          *hStdError;
	} STARTUPINFOA, *LPSTARTUPINFOA;

	void WIN_FUNC GetStartupInfoA(STARTUPINFOA *lpStartupInfo) {
		DEBUG_LOG("GetStartupInfoA\n");
		memset(lpStartupInfo, 0, sizeof(STARTUPINFOA));
	}

	unsigned short WIN_FUNC GetFileType(void *hFile) {
		DEBUG_LOG("GetFileType %p\n", hFile);
		return 2; // FILE_TYPE_CHAR
	}

	unsigned int WIN_FUNC SetHandleCount(unsigned int uNumber) {
		DEBUG_LOG("SetHandleCount %p\n", uNumber);
		return uNumber + 10;
	}

	unsigned int WIN_FUNC GetACP() {
		DEBUG_LOG("GetACP\n");
		// return 65001; // utf-8
		// return 437;   // OEM United States
		// return 1200;  // Unicode (BMP of ISO 10646)
		// return 850; 	 // OEM Multilingual Latin 1; Western European (DOS)
		return 28591; // ISO/IEC 8859-1
	}

	typedef struct _cpinfo {
	  unsigned int  MaxCharSize;
	  unsigned char DefaultChar[2];
	  unsigned char LeadByte[12];
	} CPINFO, *LPCPINFO;

	unsigned int WIN_FUNC GetCPInfo(unsigned int codePage, CPINFO* lpCPInfo) {
		DEBUG_LOG("GetCPInfo: %u\n", codePage);
		lpCPInfo->MaxCharSize = 1;
		lpCPInfo->DefaultChar[0] = 0;
		return 1; // success
	}

	unsigned int WIN_FUNC WideCharToMultiByte(unsigned int codePage, unsigned int dwFlags, uint16_t *lpWideCharStr, int cchWideChar, char *lpMultiByteStr, int cbMultiByte, char *lpDefaultChar, unsigned int *lpUsedDefaultChar) {
		DEBUG_LOG("WideCharToMultiByte(codePage=%u, flags=%x, wcs=%p, wideChar=%d, mbs=%p, multiByte=%d, defaultChar=%p, usedDefaultChar=%p)\n", codePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);

		if (cchWideChar == -1) {
			// determine how long the string actually is
			cchWideChar = 0;
			while (lpWideCharStr[cchWideChar] != 0)
				++cchWideChar;
		}

		if (cbMultiByte == 0) {
			return cchWideChar + 1;
		}
		for (int i = 0; i < cchWideChar; i++) {
			lpMultiByteStr[i] = lpWideCharStr[i];
		}
		lpMultiByteStr[cchWideChar] = 0;
		DEBUG_LOG("Converted string: [%s]\n", lpMultiByteStr);

		return cbMultiByte;
	}

	unsigned int WIN_FUNC FreeEnvironmentStringsW(void *penv) {
		DEBUG_LOG("FreeEnvironmentStringsW: %p\n", penv);
		free(penv); // ?
		return 1;
	}

	unsigned int WIN_FUNC IsProcessorFeaturePresent(unsigned int processorFeature) {
		DEBUG_LOG("IsProcessorFeaturePresent: %u\n", processorFeature);

		if (processorFeature == 0) // PF_FLOATING_POINT_PRECISION_ERRATA
			return 1;

		// sure, we have that feature...
		return 1;
	}

	void *WIN_FUNC GetProcAddress(void *hModule, char *lpProcName) {
		DEBUG_LOG("GetProcAddress: %s from %p\n", lpProcName, hModule);

		if ((unsigned int)hModule == 1) {
			if (strcmp(lpProcName, "IsProcessorFeaturePresent") == 0) return (void *) IsProcessorFeaturePresent;
		}

		return NULL;
	}

	void *WIN_FUNC HeapAlloc(void *hHeap, unsigned int dwFlags, size_t dwBytes) {
		DEBUG_LOG("HeapAlloc(heap=%p, flags=%x, bytes=%u)\n", hHeap, dwFlags, dwBytes);

		void *mem = malloc(dwBytes);
		if (mem && (dwFlags & 8))
			memset(mem, 0, dwBytes);

		DEBUG_LOG("HeapAlloc returning %p\n", mem);
		return mem;
	}

	unsigned int WIN_FUNC HeapFree(void *hHeap, unsigned int dwFlags, void *lpMem) {
		DEBUG_LOG("HeapFree(heap=%p, flags=%x, mem=%p)\n", hHeap, dwFlags, lpMem);
		free(lpMem);
		return 1;
	}
}

void *wibo::resolveKernel32(const char *name) {
	if (strcmp(name, "GetLastError") == 0) return (void *) kernel32::GetLastError;
	if (strcmp(name, "GetCurrentProcess") == 0) return (void *) kernel32::GetCurrentProcess;
	if (strcmp(name, "ExitProcess") == 0) return (void *) kernel32::ExitProcess;
	if (strcmp(name, "CreateProcessA") == 0) return (void *) kernel32::CreateProcessA;
	if (strcmp(name, "GetSystemDefaultLangID") == 0) return (void *) kernel32::GetSystemDefaultLangID;
	if (strcmp(name, "InitializeCriticalSection") == 0) return (void *) kernel32::InitializeCriticalSection;
	if (strcmp(name, "DeleteCriticalSection") == 0) return (void *) kernel32::DeleteCriticalSection;
	if (strcmp(name, "EnterCriticalSection") == 0) return (void *) kernel32::EnterCriticalSection;
	if (strcmp(name, "LeaveCriticalSection") == 0) return (void *) kernel32::LeaveCriticalSection;
	if (strcmp(name, "GlobalAlloc") == 0) return (void *) kernel32::GlobalAlloc;
	if (strcmp(name, "GlobalReAlloc") == 0) return (void *) kernel32::GlobalReAlloc;
	if (strcmp(name, "GlobalFree") == 0) return (void *) kernel32::GlobalFree;
	if (strcmp(name, "GlobalFlags") == 0) return (void *) kernel32::GlobalFlags;
	if (strcmp(name, "TlsAlloc") == 0) return (void *) kernel32::TlsAlloc;
	if (strcmp(name, "TlsFree") == 0) return (void *) kernel32::TlsFree;
	if (strcmp(name, "TlsGetValue") == 0) return (void *) kernel32::TlsGetValue;
	if (strcmp(name, "TlsSetValue") == 0) return (void *) kernel32::TlsSetValue;
	if (strcmp(name, "GetCommandLineA") == 0) return (void *) kernel32::GetCommandLineA;
	if (strcmp(name, "GetEnvironmentStrings") == 0) return (void *) kernel32::GetEnvironmentStrings;
	if (strcmp(name, "FreeEnvironmentStringsA") == 0) return (void *) kernel32::FreeEnvironmentStringsA;
	if (strcmp(name, "GetStdHandle") == 0) return (void *) kernel32::GetStdHandle;
	if (strcmp(name, "DuplicateHandle") == 0) return (void *) kernel32::DuplicateHandle;
	if (strcmp(name, "CloseHandle") == 0) return (void *) kernel32::CloseHandle;
	if (strcmp(name, "GetFullPathNameA") == 0) return (void *) kernel32::GetFullPathNameA;
	if (strcmp(name, "FindFirstFileA") == 0) return (void *) kernel32::FindFirstFileA;
	if (strcmp(name, "GetFileAttributesA") == 0) return (void *) kernel32::GetFileAttributesA;
	if (strcmp(name, "WriteFile") == 0) return (void *) kernel32::WriteFile;
	if (strcmp(name, "ReadFile") == 0) return (void *) kernel32::ReadFile;
	if (strcmp(name, "CreateFileA") == 0) return (void *) kernel32::CreateFileA;
	if (strcmp(name, "DeleteFileA") == 0) return (void *) kernel32::DeleteFileA;
	if (strcmp(name, "SetFilePointer") == 0) return (void *) kernel32::SetFilePointer;
	if (strcmp(name, "GetFileSize") == 0) return (void *) kernel32::GetFileSize;
	if (strcmp(name, "GetFileTime") == 0) return (void *) kernel32::GetFileTime;
	if (strcmp(name, "GetSystemTime") == 0) return (void *) kernel32::GetSystemTime;
	if (strcmp(name, "GetLocalTime") == 0) return (void *) kernel32::GetLocalTime;
	if (strcmp(name, "SystemTimeToFileTime") == 0) return (void *) kernel32::SystemTimeToFileTime;
	if (strcmp(name, "GetTickCount") == 0) return (void *) kernel32::GetTickCount;
	if (strcmp(name, "GetTimeZoneInformation") == 0) return (void *) kernel32::GetTimeZoneInformation;
	if (strcmp(name, "SetConsoleCtrlHandler") == 0) return (void *) kernel32::SetConsoleCtrlHandler;
	if (strcmp(name, "GetConsoleScreenBufferInfo") == 0) return (void *) kernel32::GetConsoleScreenBufferInfo;
	if (strcmp(name, "GetSystemDirectoryA") == 0) return (void *) kernel32::GetSystemDirectoryA;
	if (strcmp(name, "GetWindowsDirectoryA") == 0) return (void *) kernel32::GetWindowsDirectoryA;
	if (strcmp(name, "GetCurrentDirectoryA") == 0) return (void *) kernel32::GetCurrentDirectoryA;
	if (strcmp(name, "GetModuleHandleA") == 0) return (void *) kernel32::GetModuleHandleA;
	if (strcmp(name, "GetModuleFileNameA") == 0) return (void *) kernel32::GetModuleFileNameA;
	if (strcmp(name, "FindResourceA") == 0) return (void *) kernel32::FindResourceA;
	if (strcmp(name, "LoadResource") == 0) return (void *) kernel32::LoadResource;
	if (strcmp(name, "LockResource") == 0) return (void *) kernel32::LockResource;
	if (strcmp(name, "SizeofResource") == 0) return (void *) kernel32::SizeofResource;
	if (strcmp(name, "LoadLibraryA") == 0) return (void *) kernel32::LoadLibraryA;
	if (strcmp(name, "FreeLibrary") == 0) return (void *) kernel32::FreeLibrary;
	if (strcmp(name, "GetVersion") == 0) return (void *) kernel32::GetVersion;
	if (strcmp(name, "HeapCreate") == 0) return (void *) kernel32::HeapCreate;
	if (strcmp(name, "VirtualAlloc") == 0) return (void *) kernel32::VirtualAlloc;
	if (strcmp(name, "GetStartupInfoA") == 0) return (void *) kernel32::GetStartupInfoA;
	if (strcmp(name, "GetFileType") == 0) return (void *) kernel32::GetFileType;
	if (strcmp(name, "SetHandleCount") == 0) return (void *) kernel32::SetHandleCount;
	if (strcmp(name, "GetACP") == 0) return (void *) kernel32::GetACP;
	if (strcmp(name, "GetCPInfo") == 0) return (void *) kernel32::GetCPInfo;
	if (strcmp(name, "GetEnvironmentStringsW") == 0) return (void *) kernel32::GetEnvironmentStringsW;
	if (strcmp(name, "WideCharToMultiByte") == 0) return (void *) kernel32::WideCharToMultiByte;
	if (strcmp(name, "FreeEnvironmentStringsW") == 0) return (void *) kernel32::FreeEnvironmentStringsW;
	if (strcmp(name, "GetProcAddress") == 0) return (void *) kernel32::GetProcAddress;
	if (strcmp(name, "HeapAlloc") == 0) return (void *) kernel32::HeapAlloc;
	if (strcmp(name, "HeapFree") == 0) return (void *) kernel32::HeapFree;

	return 0;
}
