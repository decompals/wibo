#pragma once

#include "types.h"

using PIO_APC_ROUTINE = PVOID;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		GUEST_PTR Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

enum PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
};

enum FS_INFORMATION_CLASS {
	FileFsVolumeInformation = 1,
	FileFsLabelInformation = 2,
	FileFsSizeInformation = 3,
	FileFsDeviceInformation = 4,
	FileFsAttributeInformation = 5,
	FileFsControlInformation = 6,
	FileFsFullSizeInformation = 7,
};

enum OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation = 0,
	ObjectNameInformation = 1,
	ObjectTypeInformation = 2,
};

struct OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	GUEST_PTR ObjectName;
	ULONG Attributes;
	GUEST_PTR SecurityDescriptor;
	GUEST_PTR SecurityQualityOfService;
};

using POBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES *;

struct FILE_FS_VOLUME_INFORMATION {
	LARGE_INTEGER VolumeCreationTime;
	ULONG VolumeSerialNumber;
	ULONG VolumeLabelLength;
	BOOLEAN SupportsObjects;
	BOOLEAN Reserved;
	WCHAR VolumeLabel[1];
};
using PFILE_FS_VOLUME_INFORMATION = FILE_FS_VOLUME_INFORMATION *;

struct FILE_FS_SIZE_INFORMATION {
	LARGE_INTEGER TotalAllocationUnits;
	LARGE_INTEGER AvailableAllocationUnits;
	ULONG SectorsPerAllocationUnit;
	ULONG BytesPerSector;
};
using PFILE_FS_SIZE_INFORMATION = FILE_FS_SIZE_INFORMATION *;

struct FILE_FS_DEVICE_INFORMATION {
	ULONG DeviceType;
	ULONG Characteristics;
};
using PFILE_FS_DEVICE_INFORMATION = FILE_FS_DEVICE_INFORMATION *;

struct FILE_FS_ATTRIBUTE_INFORMATION {
	ULONG FileSystemAttributes;
	ULONG MaximumComponentNameLength;
	ULONG FileSystemNameLength;
	WCHAR FileSystemName[1];
};
using PFILE_FS_ATTRIBUTE_INFORMATION = FILE_FS_ATTRIBUTE_INFORMATION *;

struct FILE_FS_FULL_SIZE_INFORMATION {
	LARGE_INTEGER TotalAllocationUnits;
	LARGE_INTEGER CallerAvailableAllocationUnits;
	LARGE_INTEGER ActualAvailableAllocationUnits;
	ULONG SectorsPerAllocationUnit;
	ULONG BytesPerSector;
};
using PFILE_FS_FULL_SIZE_INFORMATION = FILE_FS_FULL_SIZE_INFORMATION *;

struct RTL_OSVERSIONINFOW {
	ULONG dwOSVersionInfoSize;
	ULONG dwMajorVersion;
	ULONG dwMinorVersion;
	ULONG dwBuildNumber;
	ULONG dwPlatformId;
	WCHAR szCSDVersion[128];
};

using PRTL_OSVERSIONINFOW = RTL_OSVERSIONINFOW *;

namespace ntdll {

PVOID CDECL memset(PVOID dest, int ch, SIZE_T count);
NTSTATUS WINAPI NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
						   PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
						   PULONG Key);
NTSTATUS WINAPI NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
							PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
							PULONG Key);
NTSTATUS WINAPI NtAllocateVirtualMemory(HANDLE ProcessHandle, guest_ptr<> *BaseAddress, ULONG_PTR ZeroBits,
										PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTSTATUS WINAPI NtProtectVirtualMemory(HANDLE ProcessHandle, guest_ptr<> *BaseAddress, PSIZE_T NumberOfBytesToProtect,
									   ULONG NewAccessProtection, PULONG OldAccessProtection);
NTSTATUS WINAPI NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
									   ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
NTSTATUS WINAPI NtQueryVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation,
											 ULONG Length, FS_INFORMATION_CLASS FsInformationClass);
NTSTATUS WINAPI NtCreateFile(PHANDLE FileHandle, DWORD DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
							 PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
							 ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer,
							 ULONG EaLength);
NTSTATUS WINAPI NtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation,
							  ULONG ObjectInformationLength, PULONG ReturnLength);
NTSTATUS WINAPI NtQuerySystemTime(PLARGE_INTEGER SystemTime);
NTSTATUS WINAPI NtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation,
										 ULONG SystemInformationLength, PULONG ReturnLength);
BOOLEAN WINAPI RtlTimeToSecondsSince1970(PLARGE_INTEGER Time, PULONG ElapsedSeconds);
VOID WINAPI RtlInitializeBitMap(PRTL_BITMAP BitMapHeader, PULONG BitMapBuffer, ULONG SizeOfBitMap);
VOID WINAPI RtlSetBits(PRTL_BITMAP BitMapHeader, ULONG StartingIndex, ULONG NumberToSet);
BOOLEAN WINAPI RtlAreBitsSet(PRTL_BITMAP BitMapHeader, ULONG StartingIndex, ULONG Length);
BOOLEAN WINAPI RtlAreBitsClear(PRTL_BITMAP BitMapHeader, ULONG StartingIndex, ULONG Length);
NTSTATUS WINAPI RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);
ULONG WINAPI RtlIsDosDeviceName_U(PWSTR DeviceName);
ULONG WINAPI RtlNtStatusToDosError(NTSTATUS Status);
NTSTATUS WINAPI NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
										  PVOID ProcessInformation, ULONG ProcessInformationLength,
										  PULONG ReturnLength);
NTSTATUS WINAPI LdrAddRefDll(ULONG Flags, HMODULE Module);

} // namespace ntdll
