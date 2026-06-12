#pragma once
#include "types.h"
#include "ntdll.h"

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	UNICODE_STRING *ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

namespace ntdll {

BOOLEAN WINAPI RtlCreateUnicodeString(UNICODE_STRING *DestinationString, const WCHAR *SourceString);
VOID WINAPI RtlFreeUnicodeString(UNICODE_STRING *UnicodeString);
NTSTATUS WINAPI NtClose(HANDLE Handle);
NTSTATUS WINAPI NtCreateFile(HANDLE *FileHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES *ObjectAttributes,
							 PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
							 ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer,
							 ULONG EaLength);
NTSTATUS WINAPI NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
									 PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
									 ULONG FileInformationClass, ULONG ReturnSingleEntry, UNICODE_STRING *FileName,
									 ULONG RestartScan);

} // namespace ntdll
