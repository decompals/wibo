.intel_syntax noprefix

.equ TEB_SELF, 0x18     # Self
.equ TEB_FS_SEL, 0xf98  # CurrentFsSelector
.equ TEB_GS_SEL, 0xf9a  # CurrentGsSelector

#ifdef __i386__

.equ TEB_SP, 0xf9c      # CurrentStackPointer

#endif // __i386__

#ifdef __x86_64__

.equ TEB_SP, 0xfa0      # CurrentStackPointer
.equ TEB_FSBASE, 0xfa8  # HostFsBase
.equ TEB_GSBASE, 0xfb0  # HostGsBase

#ifdef __linux__
.equ CS_32, 0x23        # 32-bit code segment (Linux)
.equ CS_64, 0x33        # 64-bit code segment (Linux)
.equ DS_32, 0x2b        # 32-bit data segment (Linux)
#elif defined(__APPLE__)
.equ CS_64, 0x2b        # 64-bit code segment (macOS)
#else
#error "Unsupported platform"
#endif

.macro LJMP32 teb_reg
#ifdef __APPLE__
#define m1632 m1632_\@
.data
m1632:
    .long 1f             # 32-bit code offset
    .long 0              # 32-bit code segment (filled in at runtime)
.text
    mov r10w, word ptr [\teb_reg+TEB_FS_SEL]
    sub r10w, 16
    mov word ptr [rip+m1632+4], r10w
    jmp fword ptr [rip+m1632]
#else
	jmp fword ptr [rip] # far jump into 32-bit code
    .long 1f            # 32-bit code offset
    .word CS_32         # 32-bit code segment
#endif
.code32
1:
    endbr32
.endm

.macro LJMP64 teb_reg
// Annoyingly, we can't assemble this in Intel syntax
.att_syntax prefix
    ljmp $CS_64, $1f
.intel_syntax noprefix
.code64
1:
    endbr64
.endm

#endif // __x86_64__

.macro GET_TEB_HOST reg

#if defined(__APPLE__) && defined(__x86_64__)
// TLS slot 6 reserved for Win64 compatibility
// https://github.com/apple/darwin-libpthread/blob/03c4628c8940cca6fd6a82957f683af804f62e7f/private/tsd_private.h#L92-L97
mov \reg, gs:[0x30]
#elif defined(__linux__) && defined(__x86_64__)
mov \reg, fs:[currentThreadTeb@tpoff]
#elif defined(__linux__) && defined(__i386__)
mov \reg, gs:[currentThreadTeb@ntpoff]
#else
#error "Unsupported platform"
#endif

.endm
