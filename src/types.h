#pragma once

#ifndef va_list
#define va_list __builtin_va_list
#endif

// On Windows, the incoming stack is aligned to a 4 byte boundary.
// force_align_arg_pointer will realign the stack to match GCC's 16 byte alignment.
#define WIN_ENTRY __attribute__((cdecl, force_align_arg_pointer))
#define WIN_FUNC __attribute__((stdcall, force_align_arg_pointer))

// Annotation macros for code generation
#ifdef WIBO_CODEGEN
#define WIBO_ANNOTATE(x) __attribute__((annotate(x)))
#else
#define WIBO_ANNOTATE(x)
#endif

// SAL-style directionality
#define _In_ WIBO_ANNOTATE("SAL:in")
#define _Out_ WIBO_ANNOTATE("SAL:out")
#define _Inout_ WIBO_ANNOTATE("SAL:inout")
#define _In_opt_ WIBO_ANNOTATE("SAL:in_opt")
#define _Out_opt_ WIBO_ANNOTATE("SAL:out_opt")

// Byte-counted buffers
#define _In_reads_bytes_(n) WIBO_ANNOTATE("SAL:in_bcount(" #n ")")
#define _Out_writes_bytes_(n) WIBO_ANNOTATE("SAL:out_bcount(" #n ")")

// Codegen annotation for calling convention
#define _CC_CDECL WIBO_ANNOTATE("CC:cdecl")
#define _CC_STDCALL WIBO_ANNOTATE("CC:stdcall")

// Instructs codegen to convert between calling conventions
#define WINAPI _CC_STDCALL __attribute__((fastcall))
#define CDECL _CC_CDECL __attribute__((fastcall))
#define CDECL_NO_CONV _CC_CDECL __attribute__((cdecl, force_align_arg_pointer))

// Used for host-to-guest calls
#define GUEST_STDCALL __attribute__((stdcall))

using VOID = void;
using HANDLE = VOID *;
using HMODULE = VOID *;
using HGLOBAL = HANDLE;
using HLOCAL = HANDLE;
using HRSRC = HANDLE;
using HINSTANCE = HANDLE;
using LPHANDLE = HANDLE *;
using PHANDLE = HANDLE *;
using HKL = HANDLE;
using PVOID = VOID *;
using LPVOID = VOID *;
using LPCVOID = const VOID *;
using FARPROC = VOID *;
using WORD = unsigned short;
using LPWORD = WORD *;
using LANGID = WORD;
using ATOM = WORD;
using DWORD = unsigned int;
using PDWORD = DWORD *;
using LPDWORD = DWORD *;
using LONG = int;
using PLONG = LONG *;
using ULONG = unsigned int;
using PULONG = ULONG *;
using LONGLONG = long long;
using ULONGLONG = unsigned long long;
using LONG_PTR = long;
static_assert(sizeof(LONG_PTR) == sizeof(void *), "LONG_PTR must be pointer-sized");
using ULONG_PTR = unsigned long;
static_assert(sizeof(ULONG_PTR) == sizeof(void *), "ULONG_PTR must be pointer-sized");
using UINT_PTR = unsigned long;
static_assert(sizeof(UINT_PTR) == sizeof(void *), "UINT_PTR must be pointer-sized");
using DWORD_PTR = ULONG_PTR;
using PDWORD_PTR = DWORD_PTR *;
using SHORT = short;
using USHORT = unsigned short;
using CHAR = char;
using LPSTR = CHAR *;
using LPCSTR = const char *;
using LPCCH = const char *;
using WCHAR = unsigned short;
using LPWSTR = WCHAR *;
using LPCWSTR = const WCHAR *;
using LPCWCH = const WCHAR *;
using LPCH = CHAR *;
using LPWCH = WCHAR *;
using BOOL = int;
using PBOOL = BOOL *;
using LPBOOL = BOOL *;
using UCHAR = unsigned char;
using PUCHAR = UCHAR *;
using SIZE_T = ULONG_PTR;
using PSIZE_T = SIZE_T *;
using BYTE = unsigned char;
using BOOLEAN = unsigned char;
using UINT = unsigned int;
using PUINT = UINT *;
using HKEY = VOID *;
using PHKEY = HKEY *;
using PSID = VOID *;
using REGSAM = DWORD;
using LSTATUS = LONG;
using LCID = DWORD;
using LCTYPE = DWORD;
using HWINSTA = HANDLE;
using HWND = HANDLE;
using PBYTE = BYTE *;
using LPBYTE = BYTE *;
using PWSTR = WCHAR *;

using NTSTATUS = LONG;
using HRESULT = LONG;

typedef union _LARGE_INTEGER {
	struct {
		DWORD LowPart;
		LONG HighPart;
	} DUMMYSTRUCTNAME;
	struct {
		DWORD LowPart;
		LONG HighPart;
	} u;
	LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef union _ULARGE_INTEGER {
	struct {
		DWORD LowPart;
		DWORD HighPart;
	} DUMMYSTRUCTNAME;
	struct {
		DWORD LowPart;
		DWORD HighPart;
	} u;
	ULONGLONG QuadPart;
} ULARGE_INTEGER, *PULARGE_INTEGER;

struct GUID {
	DWORD Data1;
	WORD Data2;
	WORD Data3;
	BYTE Data4[8];
};
struct LUID {
	DWORD LowPart;
	LONG HighPart;
};
using PLUID = LUID *;
using LPLUID = LUID *;

constexpr BOOL TRUE = 1;
constexpr BOOL FALSE = 0;

constexpr DWORD STILL_ACTIVE = 259;

constexpr DWORD FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
constexpr DWORD FILE_FLAG_DELETE_ON_CLOSE = 0x04000000;
constexpr DWORD FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000;
constexpr DWORD FILE_FLAG_NO_BUFFERING = 0x20000000;
constexpr DWORD FILE_FLAG_OVERLAPPED = 0x40000000;
constexpr DWORD FILE_FLAG_WRITE_THROUGH = 0x80000000;

constexpr DWORD STD_INPUT_HANDLE = ((DWORD)-10);
constexpr DWORD STD_OUTPUT_HANDLE = ((DWORD)-11);
constexpr DWORD STD_ERROR_HANDLE = ((DWORD)-12);

constexpr DWORD FILE_READ_DATA = 0x00000001;
constexpr DWORD FILE_LIST_DIRECTORY = 0x00000001;
constexpr DWORD FILE_WRITE_DATA = 0x00000002;
constexpr DWORD FILE_ADD_FILE = 0x00000002;
constexpr DWORD FILE_APPEND_DATA = 0x00000004;
constexpr DWORD FILE_ADD_SUBDIRECTORY = 0x00000004;
constexpr DWORD FILE_CREATE_PIPE_INSTANCE = 0x00000004;
constexpr DWORD FILE_READ_EA = 0x00000008;
constexpr DWORD FILE_WRITE_EA = 0x00000010;
constexpr DWORD FILE_EXECUTE = 0x00000020;
constexpr DWORD FILE_TRAVERSE = 0x00000020;
constexpr DWORD FILE_DELETE_CHILD = 0x00000040;
constexpr DWORD FILE_READ_ATTRIBUTES = 0x00000080;
constexpr DWORD FILE_WRITE_ATTRIBUTES = 0x00000100;

constexpr DWORD SYNCHRONIZE = 0x00100000;
constexpr DWORD DELETE = 0x00010000;
constexpr DWORD WRITE_DAC = 0x00040000;
constexpr DWORD WRITE_OWNER = 0x00080000;
constexpr DWORD ACCESS_SYSTEM_SECURITY = 0x01000000;

constexpr DWORD STANDARD_RIGHTS_READ = 0x00020000;
constexpr DWORD STANDARD_RIGHTS_WRITE = 0x00020000;
constexpr DWORD STANDARD_RIGHTS_EXECUTE = 0x00020000;
constexpr DWORD STANDARD_RIGHTS_REQUIRED = 0x000f0000;
constexpr DWORD STANDARD_RIGHTS_ALL = 0x001f0000;

constexpr DWORD FILE_GENERIC_READ =
	STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE;
constexpr DWORD FILE_GENERIC_WRITE =
	STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE;
constexpr DWORD FILE_GENERIC_EXECUTE = STANDARD_RIGHTS_EXECUTE | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE;
constexpr DWORD FILE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF;

constexpr DWORD EVENT_ALL_ACCESS = 0x1F0003;
constexpr DWORD MUTEX_ALL_ACCESS = 0x1F0001;
constexpr DWORD SEMAPHORE_ALL_ACCESS = 0x1F0003;

constexpr DWORD GENERIC_READ = 0x80000000;
constexpr DWORD GENERIC_WRITE = 0x40000000;
constexpr DWORD GENERIC_EXECUTE = 0x20000000;
constexpr DWORD GENERIC_ALL = 0x10000000;

// Page protection constants
constexpr DWORD PAGE_NOACCESS = 0x01;
constexpr DWORD PAGE_READONLY = 0x02;
constexpr DWORD PAGE_READWRITE = 0x04;
constexpr DWORD PAGE_WRITECOPY = 0x08;
constexpr DWORD PAGE_EXECUTE = 0x10;
constexpr DWORD PAGE_EXECUTE_READ = 0x20;
constexpr DWORD PAGE_EXECUTE_READWRITE = 0x40;
constexpr DWORD PAGE_EXECUTE_WRITECOPY = 0x80;
constexpr DWORD PAGE_GUARD = 0x100;
constexpr DWORD PAGE_NOCACHE = 0x200;
constexpr DWORD PAGE_WRITECOMBINE = 0x400;

// Allocation type and memory state constants
constexpr DWORD MEM_COMMIT = 0x00001000;
constexpr DWORD MEM_RESERVE = 0x00002000;
constexpr DWORD MEM_DECOMMIT = 0x00004000;
constexpr DWORD MEM_RELEASE = 0x00008000;
constexpr DWORD MEM_FREE = 0x00010000;
constexpr DWORD MEM_PRIVATE = 0x00020000;
constexpr DWORD MEM_MAPPED = 0x00040000;
constexpr DWORD MEM_RESET = 0x00080000;
constexpr DWORD MEM_TOP_DOWN = 0x00100000;
constexpr DWORD MEM_WRITE_WATCH = 0x00200000;
constexpr DWORD MEM_PHYSICAL = 0x00400000;
constexpr DWORD MEM_RESET_UNDO = 0x01000000;
constexpr DWORD MEM_LARGE_PAGES = 0x20000000;
constexpr DWORD MEM_COALESCE_PLACEHOLDERS = 0x00000001;
constexpr DWORD MEM_PRESERVE_PLACEHOLDER = 0x00000002;
constexpr DWORD MEM_IMAGE = 0x01000000;

// File mapping access flags
constexpr DWORD FILE_MAP_COPY = 0x00000001;
constexpr DWORD FILE_MAP_WRITE = 0x00000002;
constexpr DWORD FILE_MAP_READ = 0x00000004;
constexpr DWORD FILE_MAP_EXECUTE = 0x00000020;
constexpr DWORD FILE_MAP_ALL_ACCESS = 0x000f001f;

// File share modes
constexpr DWORD FILE_SHARE_READ = 0x00000001;
constexpr DWORD FILE_SHARE_WRITE = 0x00000002;
constexpr DWORD FILE_SHARE_DELETE = 0x00000004;

constexpr DWORD PIPE_ACCESS_INBOUND = 0x00000001;
constexpr DWORD PIPE_ACCESS_OUTBOUND = 0x00000002;
constexpr DWORD PIPE_ACCESS_DUPLEX = 0x00000003;

constexpr DWORD PIPE_TYPE_BYTE = 0x00000000;
constexpr DWORD PIPE_TYPE_MESSAGE = 0x00000004;
constexpr DWORD PIPE_READMODE_BYTE = 0x00000000;
constexpr DWORD PIPE_READMODE_MESSAGE = 0x00000002;
constexpr DWORD PIPE_WAIT = 0x00000000;
constexpr DWORD PIPE_NOWAIT = 0x00000001;
constexpr DWORD PIPE_ACCEPT_REMOTE_CLIENTS = 0x00000000;
constexpr DWORD PIPE_REJECT_REMOTE_CLIENTS = 0x00000008;
constexpr DWORD PIPE_UNLIMITED_INSTANCES = 255;

constexpr SIZE_T kTlsSlotCount = 64;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _LIST_ENTRY {
	struct _LIST_ENTRY *Flink;
	struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, PRLIST_ENTRY;

typedef struct _PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef void(_CC_STDCALL *PS_POST_PROCESS_INIT_ROUTINE)();
using PPS_POST_PROCESS_INIT_ROUTINE = PS_POST_PROCESS_INIT_ROUTINE *;

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, *PPEB;

struct CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
};

struct _ACTIVATION_CONTEXT;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
	struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME *Previous;
	_ACTIVATION_CONTEXT *ActivationContext;
	ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK {
	PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
	LIST_ENTRY FrameListCache;
	ULONG Flags;
	ULONG NextCookieSequenceNumber;
	ULONG StackId;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

#define GDI_BATCH_BUFFER_SIZE 0x136
typedef struct _GDI_TEB_BATCH {
	ULONG Offset;
	HANDLE HDC;
	ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _NT_TIB {
	struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID SubSystemTib;
	union {
		PVOID FiberData;
		DWORD Version;
	} DUMMYUNIONNAME;
	PVOID ArbitraryUserPointer;
	struct _NT_TIB *Self;
} NT_TIB, *PNT_TIB;

typedef struct _TEB {
	NT_TIB Tib;
	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB Peb;
	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG Win32ClientInfo[31]; /* used for user32 private data in Wine */
	PVOID WOW32Reserved;
	ULONG CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	PVOID SystemReserved1[54]; /* used for kernel32 private data in Wine */
	PVOID Spare1;
	LONG ExceptionCode;
	PVOID ActivationContextStackPointer;
	BYTE SpareBytes1[36];
	PVOID SystemReserved2[10]; /* used for ntdll private data in Wine */
	GDI_TEB_BATCH GdiTebBatch;
	ULONG gdiRgn;
	ULONG gdiPen;
	ULONG gdiBrush;
	CLIENT_ID RealClientId;
	HANDLE GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	PVOID GdiThreadLocaleInfo;
	PVOID UserReserved[5];
	PVOID glDispatchTable[280];
	ULONG glReserved1[26];
	PVOID glReserved2;
	PVOID glSectionInfo;
	PVOID glSection;
	PVOID glTable;
	PVOID glCurrentRC;
	PVOID glContext;
	ULONG LastStatusValue;
	UNICODE_STRING StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];
	PVOID DeallocationStack;
	PVOID TlsSlots[64];
	LIST_ENTRY TlsLinks;
	PVOID Vdm;
	PVOID ReservedForNtRpc;
	PVOID DbgSsReserved[2];
	ULONG HardErrorDisabled;
	PVOID Instrumentation[16];
	PVOID WinSockData;
	ULONG GdiBatchCount;
	ULONG Spare2;
	ULONG Spare3;
	ULONG Spare4;
	PVOID ReservedForOle;
	ULONG WaitingOnLoaderLock;
	PVOID Reserved5[3];
	PVOID *TlsExpansionSlots;
	// wibo
	WORD HostFsSelector;
	WORD HostGsSelector;
	PVOID HostStackBase;
	PVOID HostStackLimit;
	PVOID HostStackPointer;
} TEB, *PTEB;

#ifndef offsetof
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif

static_assert(offsetof(NT_TIB, Self) == 0x18, "Self pointer offset mismatch");
static_assert(offsetof(TEB, ThreadLocalStoragePointer) == 0x2C, "TLS pointer offset mismatch");
static_assert(offsetof(TEB, Peb) == 0x30, "PEB pointer offset mismatch");
static_assert(offsetof(TEB, LastErrorValue) == 0x34, "LastErrorValue offset mismatch");
static_assert(offsetof(TEB, GdiTebBatch) == 0x1FC, "GdiTebBatch offset mismatch");
static_assert(offsetof(TEB, DeallocationStack) == 0xE0C, "DeallocationStack offset mismatch");
static_assert(offsetof(TEB, TlsSlots) == 0xE10, "TLS slots offset mismatch");

typedef struct _MEMORY_BASIC_INFORMATION {
	PVOID BaseAddress;
	PVOID AllocationBase;
	DWORD AllocationProtect;
	SIZE_T RegionSize;
	DWORD State;
	DWORD Protect;
	DWORD Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
