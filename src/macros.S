.intel_syntax noprefix

.equ TEB_SELF, 0x18     # Self
.equ TEB_FS_SEL, 0xf98  # CurrentFsSelector
.equ TEB_GS_SEL, 0xf9a  # CurrentGsSelector

#ifdef __i386__

.equ TEB_SP, 0xf9c      # CurrentStackPointer

#endif // __i386__

#ifdef __x86_64__

.equ TEB_SP, 0xfa0      # CurrentStackPointer
.equ TEB_FSBASE, 0xfa8  # CurrentFsBase

.equ CS_32, 0x23        # 32-bit code segment (Linux)
.equ CS_64, 0x33        # 64-bit code segment (Linux)
.equ DS_32, 0x2b        # 32-bit data segment (Linux)

.macro LJMP32
	jmp fword ptr [rip] # far jump into 32-bit code
    .long 1f            # 32-bit code offset
    .word CS_32         # 32-bit code segment (Linux)
.code32
1:
    endbr32
.endm

.macro LJMP64
    push CS_64          # 64-bit code segment (Linux)
    push offset 1f      # 64-bit code offset
    retf                # far jump into 64-bit code
.code64
1:
    endbr64
.endm

#endif // __x86_64__
