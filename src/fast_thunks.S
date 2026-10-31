// Guest-mode kernel32 stubs for calls that only touch the TEB. They skip the
// FS/GS swap and stack switch the generated thunks do.

#include "macros.S"

.text

ASM_GLOBAL(fast_kernel32_GetCurrentThreadId, @function)
.code32
	mov eax, fs:[TEB_CLIENT_ID_THREAD]
	ret
ASM_END(fast_kernel32_GetCurrentThreadId)

ASM_GLOBAL(fast_kernel32_GetLastError, @function)
.code32
	mov eax, fs:[TEB_LAST_ERROR]
	ret
ASM_END(fast_kernel32_GetLastError)

ASM_GLOBAL(fast_kernel32_SetLastError, @function)
.code32
	mov eax, dword ptr [esp + 4]
	mov fs:[TEB_LAST_ERROR], eax
	ret 4
ASM_END(fast_kernel32_SetLastError)

// Uncontended and recursive acquires; anything else falls through untouched.
ASM_GLOBAL(fast_kernel32_EnterCriticalSection, @function)
.code32
	mov ecx, dword ptr [esp + 4]
	test ecx, ecx
	jz .Lenter_slow
	xor edx, edx
	mov eax, -1
	lock cmpxchg dword ptr [ecx + CS_LOCK_COUNT], edx
	jne .Lenter_owned
	mov edx, fs:[TEB_CLIENT_ID_THREAD]
	mov dword ptr [ecx + CS_OWNING_THREAD], edx
	mov dword ptr [ecx + CS_RECURSION_COUNT], 1
	ret 4
.Lenter_owned:
	mov edx, fs:[TEB_CLIENT_ID_THREAD]
	cmp dword ptr [ecx + CS_OWNING_THREAD], edx
	jne .Lenter_slow
	lock inc dword ptr [ecx + CS_LOCK_COUNT]
	inc dword ptr [ecx + CS_RECURSION_COUNT]
	ret 4
.Lenter_slow:
	jmp SYMBOL_NAME(thunk_kernel32_EnterCriticalSection)
ASM_END(fast_kernel32_EnterCriticalSection)

// Recursive and uncontended releases; waking a waiter is left to the host.
ASM_GLOBAL(fast_kernel32_LeaveCriticalSection, @function)
.code32
	mov ecx, dword ptr [esp + 4]
	test ecx, ecx
	jz .Lleave_slow
	mov eax, dword ptr [ecx + CS_RECURSION_COUNT]
	cmp eax, 1
	jle .Lleave_final
	dec eax
	mov dword ptr [ecx + CS_RECURSION_COUNT], eax
	lock dec dword ptr [ecx + CS_LOCK_COUNT]
	ret 4
.Lleave_final:
	jne .Lleave_slow
	push ebx
	mov ebx, dword ptr [ecx + CS_OWNING_THREAD]
	// Safe while still held: nobody can acquire until LockCount drops to -1.
	mov dword ptr [ecx + CS_OWNING_THREAD], 0
	mov dword ptr [ecx + CS_RECURSION_COUNT], 0
	xor eax, eax
	mov edx, -1
	lock cmpxchg dword ptr [ecx + CS_LOCK_COUNT], edx
	jne .Lleave_contended
	pop ebx
	ret 4
.Lleave_contended:
	mov dword ptr [ecx + CS_OWNING_THREAD], ebx
	mov dword ptr [ecx + CS_RECURSION_COUNT], 1
	pop ebx
.Lleave_slow:
	jmp SYMBOL_NAME(thunk_kernel32_LeaveCriticalSection)
ASM_END(fast_kernel32_LeaveCriticalSection)
