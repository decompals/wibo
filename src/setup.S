#include "macros.S"
.section .note.GNU-stack, "", @progbits
.text

#ifdef __x86_64__

# int x86_64_thread_setup(int entry_number, void *teb)
.globl x86_64_thread_setup
.type x86_64_thread_setup, @function
x86_64_thread_setup:
    push rbx                             # save rbx
	mov r8, rsp                          # save host stack
	rdfsbase r9                          # read host FS base
	mov rdx, qword ptr [rsi+TEB_SP]      # fetch guest stack
	LJMP32                               # far jump into 32-bit code
	mov ax, 0x2b                         # user data segment (Linux)
	mov ds, ax                           # setup data segment
	mov es, ax                           # setup extra segment
	mov esp, edx                         # switch to guest stack
	sub esp, 0x10                        # sizeof(user_desc)
	mov dword ptr [esp], edi             # entry_number (arg 0)
	mov dword ptr [esp+4], esi           # base_addr (arg 1)
	mov dword ptr [esp+8], 0xffff        # limit
	mov dword ptr [esp+12], 0x41         # seg_32bit | usable
	mov ebx, esp                         # &user_desc
	mov eax, 0xf3                        # SYS_set_thread_area
	int 0x80                             # syscall
	test eax, eax                        # check for error
	jnz 1f                               # skip selector setup
	mov eax, dword ptr [esp]             # entry_number
	cmp eax, -1                          # check for invalid entry_number
	jz 2f                                # skip selector setup
	lea ebx, [eax*8+3]                   # create selector
	mov fs, bx                           # setup fs segment
	mov word ptr [esi+TEB_FS_SEL], bx    # save selector
	jmp 2f                               # skip error handling
1:
    mov eax, -1                          # return -1
2:
	add esp, 0x10                        # cleanup stack
	LJMP64                               # far jump into 64-bit code
    cdqe                                 # sign-extend eax to rax
	mov rsp, r8                          # switch to host stack
	wrfsbase r9                          # restore host FS base
	pop rbx                              # restore rbx
	ret
.size x86_64_thread_setup, .-x86_64_thread_setup

#endif // __x86_64__

.altmacro
.code32

.macro stubThunkX number
#ifdef __x86_64__
.globl _Z9stubThunkILm\()\number\()EEvv
.type  _Z9stubThunkILm\()\number\()EEvv, @function
_Z9stubThunkILm\()\number\()EEvv:
#else
.globl _Z9stubThunkILj\()\number\()EEvv
.type  _Z9stubThunkILj\()\number\()EEvv, @function
_Z9stubThunkILj\()\number\()EEvv:
#endif
    pop eax
    push \number
    push eax
    jmp thunk_entry_stubBase
.endm

.set i, 0
.rept 256
    stubThunkX %i
    .set i, i+1
.endr
