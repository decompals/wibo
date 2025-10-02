#include "common.h"

#include "kernel32/debugapi.h"
#include "kernel32/errhandlingapi.h"
#include "kernel32/fibersapi.h"
#include "kernel32/fileapi.h"
#include "kernel32/handleapi.h"
#include "kernel32/heapapi.h"
#include "kernel32/interlockedapi.h"
#include "kernel32/ioapiset.h"
#include "kernel32/libloaderapi.h"
#include "kernel32/memoryapi.h"
#include "kernel32/processenv.h"
#include "kernel32/processthreadsapi.h"
#include "kernel32/profileapi.h"
#include "kernel32/stringapiset.h"
#include "kernel32/synchapi.h"
#include "kernel32/sysinfoapi.h"
#include "kernel32/timezoneapi.h"
#include "kernel32/winbase.h"
#include "kernel32/wincon.h"
#include "kernel32/winnls.h"
#include "kernel32/winnt.h"
#include "kernel32/wow64apiset.h"

static void *resolveByName(const char *name) {
	// errhandlingapi.h
	if (strcmp(name, "GetLastError") == 0)
		return (void *)kernel32::GetLastError;
	if (strcmp(name, "SetLastError") == 0)
		return (void *)kernel32::SetLastError;
	if (strcmp(name, "IsBadReadPtr") == 0)
		return (void *)kernel32::IsBadReadPtr;
	if (strcmp(name, "IsBadWritePtr") == 0)
		return (void *)kernel32::IsBadWritePtr;
	if (strcmp(name, "RaiseException") == 0)
		return (void *)kernel32::RaiseException;
	if (strcmp(name, "AddVectoredExceptionHandler") == 0)
		return (void *)kernel32::AddVectoredExceptionHandler;
	if (strcmp(name, "SetUnhandledExceptionFilter") == 0)
		return (void *)kernel32::SetUnhandledExceptionFilter;
	if (strcmp(name, "UnhandledExceptionFilter") == 0)
		return (void *)kernel32::UnhandledExceptionFilter;
	if (strcmp(name, "SetErrorMode") == 0)
		return (void *)kernel32::SetErrorMode;

	// processthreadsapi.h
	if (strcmp(name, "IsProcessorFeaturePresent") == 0)
		return (void *)kernel32::IsProcessorFeaturePresent;
	if (strcmp(name, "GetCurrentProcess") == 0)
		return (void *)kernel32::GetCurrentProcess;
	if (strcmp(name, "GetCurrentProcessId") == 0)
		return (void *)kernel32::GetCurrentProcessId;
	if (strcmp(name, "GetCurrentThreadId") == 0)
		return (void *)kernel32::GetCurrentThreadId;
	if (strcmp(name, "ExitProcess") == 0)
		return (void *)kernel32::ExitProcess;
	if (strcmp(name, "TerminateProcess") == 0)
		return (void *)kernel32::TerminateProcess;
	if (strcmp(name, "GetExitCodeProcess") == 0)
		return (void *)kernel32::GetExitCodeProcess;
	if (strcmp(name, "CreateProcessW") == 0)
		return (void *)kernel32::CreateProcessW;
	if (strcmp(name, "CreateProcessA") == 0)
		return (void *)kernel32::CreateProcessA;
	if (strcmp(name, "CreateThread") == 0)
		return (void *)kernel32::CreateThread;
	if (strcmp(name, "ExitThread") == 0)
		return (void *)kernel32::ExitThread;
	if (strcmp(name, "GetExitCodeThread") == 0)
		return (void *)kernel32::GetExitCodeThread;
	if (strcmp(name, "TlsAlloc") == 0)
		return (void *)kernel32::TlsAlloc;
	if (strcmp(name, "TlsFree") == 0)
		return (void *)kernel32::TlsFree;
	if (strcmp(name, "TlsGetValue") == 0)
		return (void *)kernel32::TlsGetValue;
	if (strcmp(name, "TlsSetValue") == 0)
		return (void *)kernel32::TlsSetValue;
	if (strcmp(name, "GetStartupInfoA") == 0)
		return (void *)kernel32::GetStartupInfoA;
	if (strcmp(name, "GetStartupInfoW") == 0)
		return (void *)kernel32::GetStartupInfoW;
	if (strcmp(name, "SetThreadStackGuarantee") == 0)
		return (void *)kernel32::SetThreadStackGuarantee;
	if (strcmp(name, "GetCurrentThread") == 0)
		return (void *)kernel32::GetCurrentThread;
	if (strcmp(name, "GetThreadTimes") == 0)
		return (void *)kernel32::GetThreadTimes;
	if (strcmp(name, "SetThreadDescription") == 0)
		return (void *)kernel32::SetThreadDescription;
	if (strcmp(name, "SetThreadAffinityMask") == 0)
		return (void *)kernel32::SetThreadAffinityMask;
	if (strcmp(name, "ResumeThread") == 0)
		return (void *)kernel32::ResumeThread;
	if (strcmp(name, "SetThreadPriority") == 0)
		return (void *)kernel32::SetThreadPriority;
	if (strcmp(name, "GetThreadPriority") == 0)
		return (void *)kernel32::GetThreadPriority;
	if (strcmp(name, "GetProcessAffinityMask") == 0)
		return (void *)kernel32::GetProcessAffinityMask;
	if (strcmp(name, "SetProcessAffinityMask") == 0)
		return (void *)kernel32::SetProcessAffinityMask;

	// winnls.h
	if (strcmp(name, "GetSystemDefaultLangID") == 0)
		return (void *)kernel32::GetSystemDefaultLangID;
	if (strcmp(name, "GetUserDefaultUILanguage") == 0)
		return (void *)kernel32::GetUserDefaultUILanguage;
	if (strcmp(name, "GetACP") == 0)
		return (void *)kernel32::GetACP;
	if (strcmp(name, "GetCPInfo") == 0)
		return (void *)kernel32::GetCPInfo;
	if (strcmp(name, "CompareStringA") == 0)
		return (void *)kernel32::CompareStringA;
	if (strcmp(name, "CompareStringW") == 0)
		return (void *)kernel32::CompareStringW;
	if (strcmp(name, "IsValidLocale") == 0)
		return (void *)kernel32::IsValidLocale;
	if (strcmp(name, "IsValidCodePage") == 0)
		return (void *)kernel32::IsValidCodePage;
	if (strcmp(name, "LCMapStringW") == 0)
		return (void *)kernel32::LCMapStringW;
	if (strcmp(name, "LCMapStringA") == 0)
		return (void *)kernel32::LCMapStringA;
	if (strcmp(name, "GetLocaleInfoA") == 0)
		return (void *)kernel32::GetLocaleInfoA;
	if (strcmp(name, "GetLocaleInfoW") == 0)
		return (void *)kernel32::GetLocaleInfoW;
	if (strcmp(name, "EnumSystemLocalesA") == 0)
		return (void *)kernel32::EnumSystemLocalesA;
	if (strcmp(name, "GetUserDefaultLCID") == 0)
		return (void *)kernel32::GetUserDefaultLCID;
	if (strcmp(name, "IsDBCSLeadByte") == 0)
		return (void *)kernel32::IsDBCSLeadByte;
	if (strcmp(name, "IsDBCSLeadByteEx") == 0)
		return (void *)kernel32::IsDBCSLeadByteEx;

	// synchapi.h
	if (strcmp(name, "InitializeCriticalSection") == 0)
		return (void *)kernel32::InitializeCriticalSection;
	if (strcmp(name, "InitializeCriticalSectionEx") == 0)
		return (void *)kernel32::InitializeCriticalSectionEx;
	if (strcmp(name, "InitializeCriticalSectionAndSpinCount") == 0)
		return (void *)kernel32::InitializeCriticalSectionAndSpinCount;
	if (strcmp(name, "DeleteCriticalSection") == 0)
		return (void *)kernel32::DeleteCriticalSection;
	if (strcmp(name, "EnterCriticalSection") == 0)
		return (void *)kernel32::EnterCriticalSection;
	if (strcmp(name, "LeaveCriticalSection") == 0)
		return (void *)kernel32::LeaveCriticalSection;
	if (strcmp(name, "InitOnceBeginInitialize") == 0)
		return (void *)kernel32::InitOnceBeginInitialize;
	if (strcmp(name, "InitOnceComplete") == 0)
		return (void *)kernel32::InitOnceComplete;
	if (strcmp(name, "AcquireSRWLockShared") == 0)
		return (void *)kernel32::AcquireSRWLockShared;
	if (strcmp(name, "ReleaseSRWLockShared") == 0)
		return (void *)kernel32::ReleaseSRWLockShared;
	if (strcmp(name, "AcquireSRWLockExclusive") == 0)
		return (void *)kernel32::AcquireSRWLockExclusive;
	if (strcmp(name, "ReleaseSRWLockExclusive") == 0)
		return (void *)kernel32::ReleaseSRWLockExclusive;
	if (strcmp(name, "TryAcquireSRWLockExclusive") == 0)
		return (void *)kernel32::TryAcquireSRWLockExclusive;
	if (strcmp(name, "WaitForSingleObject") == 0)
		return (void *)kernel32::WaitForSingleObject;
	if (strcmp(name, "CreateMutexA") == 0)
		return (void *)kernel32::CreateMutexA;
	if (strcmp(name, "CreateMutexW") == 0)
		return (void *)kernel32::CreateMutexW;
	if (strcmp(name, "CreateEventA") == 0)
		return (void *)kernel32::CreateEventA;
	if (strcmp(name, "CreateEventW") == 0)
		return (void *)kernel32::CreateEventW;
	if (strcmp(name, "CreateSemaphoreA") == 0)
		return (void *)kernel32::CreateSemaphoreA;
	if (strcmp(name, "CreateSemaphoreW") == 0)
		return (void *)kernel32::CreateSemaphoreW;
	if (strcmp(name, "SetEvent") == 0)
		return (void *)kernel32::SetEvent;
	if (strcmp(name, "ResetEvent") == 0)
		return (void *)kernel32::ResetEvent;
	if (strcmp(name, "ReleaseMutex") == 0)
		return (void *)kernel32::ReleaseMutex;
	if (strcmp(name, "ReleaseSemaphore") == 0)
		return (void *)kernel32::ReleaseSemaphore;
	if (strcmp(name, "Sleep") == 0)
		return (void *)kernel32::Sleep;

	// winbase.h
	if (strcmp(name, "GlobalAlloc") == 0)
		return (void *)kernel32::GlobalAlloc;
	if (strcmp(name, "GlobalReAlloc") == 0)
		return (void *)kernel32::GlobalReAlloc;
	if (strcmp(name, "GlobalFree") == 0)
		return (void *)kernel32::GlobalFree;
	if (strcmp(name, "GlobalFlags") == 0)
		return (void *)kernel32::GlobalFlags;
	if (strcmp(name, "LocalAlloc") == 0)
		return (void *)kernel32::LocalAlloc;
	if (strcmp(name, "LocalReAlloc") == 0)
		return (void *)kernel32::LocalReAlloc;
	if (strcmp(name, "LocalFree") == 0)
		return (void *)kernel32::LocalFree;
	if (strcmp(name, "LocalHandle") == 0)
		return (void *)kernel32::LocalHandle;
	if (strcmp(name, "LocalLock") == 0)
		return (void *)kernel32::LocalLock;
	if (strcmp(name, "LocalUnlock") == 0)
		return (void *)kernel32::LocalUnlock;
	if (strcmp(name, "LocalSize") == 0)
		return (void *)kernel32::LocalSize;
	if (strcmp(name, "LocalFlags") == 0)
		return (void *)kernel32::LocalFlags;
	if (strcmp(name, "GetCurrentDirectoryA") == 0)
		return (void *)kernel32::GetCurrentDirectoryA;
	if (strcmp(name, "GetCurrentDirectoryW") == 0)
		return (void *)kernel32::GetCurrentDirectoryW;
	if (strcmp(name, "SetCurrentDirectoryA") == 0)
		return (void *)kernel32::SetCurrentDirectoryA;
	if (strcmp(name, "SetCurrentDirectoryW") == 0)
		return (void *)kernel32::SetCurrentDirectoryW;
	if (strcmp(name, "SetHandleCount") == 0)
		return (void *)kernel32::SetHandleCount;
	if (strcmp(name, "FormatMessageA") == 0)
		return (void *)kernel32::FormatMessageA;
	if (strcmp(name, "GetComputerNameA") == 0)
		return (void *)kernel32::GetComputerNameA;
	if (strcmp(name, "GetComputerNameW") == 0)
		return (void *)kernel32::GetComputerNameW;
	if (strcmp(name, "EncodePointer") == 0)
		return (void *)kernel32::EncodePointer;
	if (strcmp(name, "DecodePointer") == 0)
		return (void *)kernel32::DecodePointer;
	if (strcmp(name, "SetDllDirectoryA") == 0)
		return (void *)kernel32::SetDllDirectoryA;
	if (strcmp(name, "GetLongPathNameA") == 0)
		return (void *)kernel32::GetLongPathNameA;
	if (strcmp(name, "GetLongPathNameW") == 0)
		return (void *)kernel32::GetLongPathNameW;
	if (strcmp(name, "GetDiskFreeSpaceA") == 0)
		return (void *)kernel32::GetDiskFreeSpaceA;
	if (strcmp(name, "GetDiskFreeSpaceW") == 0)
		return (void *)kernel32::GetDiskFreeSpaceW;
	if (strcmp(name, "GetDiskFreeSpaceExA") == 0)
		return (void *)kernel32::GetDiskFreeSpaceExA;
	if (strcmp(name, "GetDiskFreeSpaceExW") == 0)
		return (void *)kernel32::GetDiskFreeSpaceExW;

	// processenv.h
	if (strcmp(name, "GetCommandLineA") == 0)
		return (void *)kernel32::GetCommandLineA;
	if (strcmp(name, "GetCommandLineW") == 0)
		return (void *)kernel32::GetCommandLineW;
	if (strcmp(name, "GetEnvironmentStrings") == 0)
		return (void *)kernel32::GetEnvironmentStrings;
	if (strcmp(name, "FreeEnvironmentStringsA") == 0)
		return (void *)kernel32::FreeEnvironmentStringsA;
	if (strcmp(name, "GetEnvironmentStringsW") == 0)
		return (void *)kernel32::GetEnvironmentStringsW;
	if (strcmp(name, "FreeEnvironmentStringsW") == 0)
		return (void *)kernel32::FreeEnvironmentStringsW;
	if (strcmp(name, "GetEnvironmentVariableA") == 0)
		return (void *)kernel32::GetEnvironmentVariableA;
	if (strcmp(name, "SetEnvironmentVariableA") == 0)
		return (void *)kernel32::SetEnvironmentVariableA;
	if (strcmp(name, "SetEnvironmentVariableW") == 0)
		return (void *)kernel32::SetEnvironmentVariableW;
	if (strcmp(name, "GetEnvironmentVariableW") == 0)
		return (void *)kernel32::GetEnvironmentVariableW;
	if (strcmp(name, "GetStdHandle") == 0)
		return (void *)kernel32::GetStdHandle;
	if (strcmp(name, "SetStdHandle") == 0)
		return (void *)kernel32::SetStdHandle;

	// handleapi.h
	if (strcmp(name, "DuplicateHandle") == 0)
		return (void *)kernel32::DuplicateHandle;
	if (strcmp(name, "CloseHandle") == 0)
		return (void *)kernel32::CloseHandle;

	// wincon.h
	if (strcmp(name, "GetConsoleMode") == 0)
		return (void *)kernel32::GetConsoleMode;
	if (strcmp(name, "SetConsoleMode") == 0)
		return (void *)kernel32::SetConsoleMode;
	if (strcmp(name, "SetConsoleCtrlHandler") == 0)
		return (void *)kernel32::SetConsoleCtrlHandler;
	if (strcmp(name, "GetConsoleScreenBufferInfo") == 0)
		return (void *)kernel32::GetConsoleScreenBufferInfo;
	if (strcmp(name, "WriteConsoleW") == 0)
		return (void *)kernel32::WriteConsoleW;
	if (strcmp(name, "GetConsoleOutputCP") == 0)
		return (void *)kernel32::GetConsoleOutputCP;
	if (strcmp(name, "PeekConsoleInputA") == 0)
		return (void *)kernel32::PeekConsoleInputA;
	if (strcmp(name, "ReadConsoleInputA") == 0)
		return (void *)kernel32::ReadConsoleInputA;

	// fileapi.h
	if (strcmp(name, "GetFullPathNameA") == 0)
		return (void *)kernel32::GetFullPathNameA;
	if (strcmp(name, "GetFullPathNameW") == 0)
		return (void *)kernel32::GetFullPathNameW;
	if (strcmp(name, "GetShortPathNameA") == 0)
		return (void *)kernel32::GetShortPathNameA;
	if (strcmp(name, "GetShortPathNameW") == 0)
		return (void *)kernel32::GetShortPathNameW;
	if (strcmp(name, "FindFirstFileA") == 0)
		return (void *)kernel32::FindFirstFileA;
	if (strcmp(name, "FindFirstFileW") == 0)
		return (void *)kernel32::FindFirstFileW;
	if (strcmp(name, "FindFirstFileExA") == 0)
		return (void *)kernel32::FindFirstFileExA;
	if (strcmp(name, "FindNextFileA") == 0)
		return (void *)kernel32::FindNextFileA;
	if (strcmp(name, "FindNextFileW") == 0)
		return (void *)kernel32::FindNextFileW;
	if (strcmp(name, "FindClose") == 0)
		return (void *)kernel32::FindClose;
	if (strcmp(name, "GetFileAttributesA") == 0)
		return (void *)kernel32::GetFileAttributesA;
	if (strcmp(name, "GetFileAttributesW") == 0)
		return (void *)kernel32::GetFileAttributesW;
	if (strcmp(name, "WriteFile") == 0)
		return (void *)kernel32::WriteFile;
	if (strcmp(name, "FlushFileBuffers") == 0)
		return (void *)kernel32::FlushFileBuffers;
	if (strcmp(name, "ReadFile") == 0)
		return (void *)kernel32::ReadFile;
	if (strcmp(name, "CreateFileA") == 0)
		return (void *)kernel32::CreateFileA;
	if (strcmp(name, "CreateFileW") == 0)
		return (void *)kernel32::CreateFileW;
	if (strcmp(name, "CreateFileMappingA") == 0)
		return (void *)kernel32::CreateFileMappingA;
	if (strcmp(name, "CreateFileMappingW") == 0)
		return (void *)kernel32::CreateFileMappingW;
	if (strcmp(name, "MapViewOfFile") == 0)
		return (void *)kernel32::MapViewOfFile;
	if (strcmp(name, "UnmapViewOfFile") == 0)
		return (void *)kernel32::UnmapViewOfFile;
	if (strcmp(name, "DeleteFileA") == 0)
		return (void *)kernel32::DeleteFileA;
	if (strcmp(name, "DeleteFileW") == 0)
		return (void *)kernel32::DeleteFileW;
	if (strcmp(name, "MoveFileA") == 0)
		return (void *)kernel32::MoveFileA;
	if (strcmp(name, "MoveFileW") == 0)
		return (void *)kernel32::MoveFileW;
	if (strcmp(name, "SetFilePointer") == 0)
		return (void *)kernel32::SetFilePointer;
	if (strcmp(name, "SetFilePointerEx") == 0)
		return (void *)kernel32::SetFilePointerEx;
	if (strcmp(name, "SetEndOfFile") == 0)
		return (void *)kernel32::SetEndOfFile;
	if (strcmp(name, "CreateDirectoryA") == 0)
		return (void *)kernel32::CreateDirectoryA;
	if (strcmp(name, "RemoveDirectoryA") == 0)
		return (void *)kernel32::RemoveDirectoryA;
	if (strcmp(name, "SetFileAttributesA") == 0)
		return (void *)kernel32::SetFileAttributesA;
	if (strcmp(name, "GetFileSize") == 0)
		return (void *)kernel32::GetFileSize;
	if (strcmp(name, "GetFileTime") == 0)
		return (void *)kernel32::GetFileTime;
	if (strcmp(name, "SetFileTime") == 0)
		return (void *)kernel32::SetFileTime;
	if (strcmp(name, "GetFileType") == 0)
		return (void *)kernel32::GetFileType;
	if (strcmp(name, "FileTimeToLocalFileTime") == 0)
		return (void *)kernel32::FileTimeToLocalFileTime;
	if (strcmp(name, "LocalFileTimeToFileTime") == 0)
		return (void *)kernel32::LocalFileTimeToFileTime;
	if (strcmp(name, "DosDateTimeToFileTime") == 0)
		return (void *)kernel32::DosDateTimeToFileTime;
	if (strcmp(name, "FileTimeToDosDateTime") == 0)
		return (void *)kernel32::FileTimeToDosDateTime;
	if (strcmp(name, "GetFileInformationByHandle") == 0)
		return (void *)kernel32::GetFileInformationByHandle;
	if (strcmp(name, "GetTempFileNameA") == 0)
		return (void *)kernel32::GetTempFileNameA;
	if (strcmp(name, "GetTempPathA") == 0)
		return (void *)kernel32::GetTempPathA;

	// sysinfoapi.h
	if (strcmp(name, "GetSystemInfo") == 0)
		return (void *)kernel32::GetSystemInfo;
	if (strcmp(name, "GetSystemTime") == 0)
		return (void *)kernel32::GetSystemTime;
	if (strcmp(name, "GetLocalTime") == 0)
		return (void *)kernel32::GetLocalTime;
	if (strcmp(name, "GetSystemTimeAsFileTime") == 0)
		return (void *)kernel32::GetSystemTimeAsFileTime;
	if (strcmp(name, "GetTickCount") == 0)
		return (void *)kernel32::GetTickCount;
	if (strcmp(name, "GetSystemDirectoryA") == 0)
		return (void *)kernel32::GetSystemDirectoryA;
	if (strcmp(name, "GetWindowsDirectoryA") == 0)
		return (void *)kernel32::GetWindowsDirectoryA;
	if (strcmp(name, "GetVersion") == 0)
		return (void *)kernel32::GetVersion;
	if (strcmp(name, "GetVersionExA") == 0)
		return (void *)kernel32::GetVersionExA;

	// timezoneapi.h
	if (strcmp(name, "SystemTimeToFileTime") == 0)
		return (void *)kernel32::SystemTimeToFileTime;
	if (strcmp(name, "FileTimeToSystemTime") == 0)
		return (void *)kernel32::FileTimeToSystemTime;
	if (strcmp(name, "GetTimeZoneInformation") == 0)
		return (void *)kernel32::GetTimeZoneInformation;

	// libloaderapi.h
	if (strcmp(name, "GetModuleHandleA") == 0)
		return (void *)kernel32::GetModuleHandleA;
	if (strcmp(name, "GetModuleHandleW") == 0)
		return (void *)kernel32::GetModuleHandleW;
	if (strcmp(name, "GetModuleFileNameA") == 0)
		return (void *)kernel32::GetModuleFileNameA;
	if (strcmp(name, "GetModuleFileNameW") == 0)
		return (void *)kernel32::GetModuleFileNameW;
	if (strcmp(name, "LoadResource") == 0)
		return (void *)kernel32::LoadResource;
	if (strcmp(name, "LockResource") == 0)
		return (void *)kernel32::LockResource;
	if (strcmp(name, "SizeofResource") == 0)
		return (void *)kernel32::SizeofResource;
	if (strcmp(name, "LoadLibraryA") == 0)
		return (void *)kernel32::LoadLibraryA;
	if (strcmp(name, "LoadLibraryW") == 0)
		return (void *)kernel32::LoadLibraryW;
	if (strcmp(name, "LoadLibraryExW") == 0)
		return (void *)kernel32::LoadLibraryExW;
	if (strcmp(name, "DisableThreadLibraryCalls") == 0)
		return (void *)kernel32::DisableThreadLibraryCalls;
	if (strcmp(name, "FreeLibrary") == 0)
		return (void *)kernel32::FreeLibrary;
	if (strcmp(name, "GetProcAddress") == 0)
		return (void *)kernel32::GetProcAddress;
	if (strcmp(name, "FindResourceA") == 0)
		return (void *)kernel32::FindResourceA;
	if (strcmp(name, "FindResourceExA") == 0)
		return (void *)kernel32::FindResourceExA;
	if (strcmp(name, "FindResourceW") == 0)
		return (void *)kernel32::FindResourceW;
	if (strcmp(name, "FindResourceExW") == 0)
		return (void *)kernel32::FindResourceExW;

	// heapapi.h
	if (strcmp(name, "HeapCreate") == 0)
		return (void *)kernel32::HeapCreate;
	if (strcmp(name, "GetProcessHeap") == 0)
		return (void *)kernel32::GetProcessHeap;
	if (strcmp(name, "HeapSetInformation") == 0)
		return (void *)kernel32::HeapSetInformation;
	if (strcmp(name, "HeapAlloc") == 0)
		return (void *)kernel32::HeapAlloc;
	if (strcmp(name, "HeapDestroy") == 0)
		return (void *)kernel32::HeapDestroy;
	if (strcmp(name, "HeapReAlloc") == 0)
		return (void *)kernel32::HeapReAlloc;
	if (strcmp(name, "HeapSize") == 0)
		return (void *)kernel32::HeapSize;
	if (strcmp(name, "HeapFree") == 0)
		return (void *)kernel32::HeapFree;

	// memoryapi.h
	if (strcmp(name, "VirtualAlloc") == 0)
		return (void *)kernel32::VirtualAlloc;
	if (strcmp(name, "VirtualFree") == 0)
		return (void *)kernel32::VirtualFree;
	if (strcmp(name, "VirtualProtect") == 0)
		return (void *)kernel32::VirtualProtect;
	if (strcmp(name, "VirtualQuery") == 0)
		return (void *)kernel32::VirtualQuery;
	if (strcmp(name, "GetProcessWorkingSetSize") == 0)
		return (void *)kernel32::GetProcessWorkingSetSize;
	if (strcmp(name, "SetProcessWorkingSetSize") == 0)
		return (void *)kernel32::SetProcessWorkingSetSize;

	// stringapiset.h
	if (strcmp(name, "WideCharToMultiByte") == 0)
		return (void *)kernel32::WideCharToMultiByte;
	if (strcmp(name, "MultiByteToWideChar") == 0)
		return (void *)kernel32::MultiByteToWideChar;
	if (strcmp(name, "GetStringTypeA") == 0)
		return (void *)kernel32::GetStringTypeA;
	if (strcmp(name, "GetStringTypeW") == 0)
		return (void *)kernel32::GetStringTypeW;

	// profileapi.h
	if (strcmp(name, "QueryPerformanceCounter") == 0)
		return (void *)kernel32::QueryPerformanceCounter;
	if (strcmp(name, "QueryPerformanceFrequency") == 0)
		return (void *)kernel32::QueryPerformanceFrequency;

	// debugapi.h
	if (strcmp(name, "IsDebuggerPresent") == 0)
		return (void *)kernel32::IsDebuggerPresent;

	// interlockedapi.h
	if (strcmp(name, "InitializeSListHead") == 0)
		return (void *)kernel32::InitializeSListHead;
	if (strcmp(name, "InterlockedIncrement") == 0)
		return (void *)kernel32::InterlockedIncrement;
	if (strcmp(name, "InterlockedDecrement") == 0)
		return (void *)kernel32::InterlockedDecrement;
	if (strcmp(name, "InterlockedExchange") == 0)
		return (void *)kernel32::InterlockedExchange;
	if (strcmp(name, "InterlockedCompareExchange") == 0)
		return (void *)kernel32::InterlockedCompareExchange;

	// winnt.h
	if (strcmp(name, "RtlUnwind") == 0)
		return (void *)kernel32::RtlUnwind;

	// fibersapi.h
	if (strcmp(name, "FlsAlloc") == 0)
		return (void *)kernel32::FlsAlloc;
	if (strcmp(name, "FlsFree") == 0)
		return (void *)kernel32::FlsFree;
	if (strcmp(name, "FlsSetValue") == 0)
		return (void *)kernel32::FlsSetValue;
	if (strcmp(name, "FlsGetValue") == 0)
		return (void *)kernel32::FlsGetValue;

	// ioapiset.h
	if (strcmp(name, "GetOverlappedResult") == 0)
		return (void *)kernel32::GetOverlappedResult;

	// wow64apiset.h
	if (strcmp(name, "Wow64DisableWow64FsRedirection") == 0)
		return (void *)kernel32::Wow64DisableWow64FsRedirection;
	if (strcmp(name, "Wow64RevertWow64FsRedirection") == 0)
		return (void *)kernel32::Wow64RevertWow64FsRedirection;
	if (strcmp(name, "IsWow64Process") == 0)
		return (void *)kernel32::IsWow64Process;

	return 0;
}

wibo::Module lib_kernel32 = {
	(const char *[]){
		"kernel32",
		nullptr,
	},
	resolveByName,
	nullptr,
};
