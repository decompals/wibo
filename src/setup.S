#include "macros.S"
.text

#ifdef __APPLE__
.zerofill RESV32, RESV32, _wibo_reserve, 0x7E000000 - 0x1000
.no_dead_strip _wibo_reserve
#endif

#if defined(__x86_64__) && defined(__linux__)

# void installSelectors(TEB *teb)
# Installs ds/es selectors in 32-bit mode
ASM_GLOBAL(installSelectors, @function)
	mov r8, rsp                             # save host stack
	mov rdx, qword ptr [rdi+TEB_SP]         # fetch guest stack
	mov ax, cs                              # fetch host code segment selector
	mov word ptr [rdi+TEB_HOST_CS_SEL], ax  # store host code segment selector
	mov ax, word ptr [rdi+TEB_DS_SEL]       # user data segment selector
	LJMP32 rdi                              # far jump into 32-bit code
	mov ds, ax                              # setup data segment
	mov es, ax                              # setup extra segment
	mov esp, edx                            # switch to guest stack
	LJMP64 edi                              # far jump into 64-bit code
	mov rsp, r8                             # switch to host stack
	ret
ASM_END(installSelectors)

# int setThreadArea64(int entryNumber, TEB *teb)
# Runs syscall SYS_set_thread_area in 32-bit mode
ASM_GLOBAL(setThreadArea64, @function)
	push rbx                             # save rbx
	mov r8, rsp                          # save host stack
	mov rdx, qword ptr [rsi+TEB_SP]      # fetch guest stack
	LJMP32 rsi                           # far jump into 32-bit code
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
	jnz 1f                               # skip if error
	mov eax, dword ptr [esp]             # entry_number
1:
	add esp, 0x10                        # cleanup stack
	LJMP64 esi                           # far jump into 64-bit code
	cdqe                                 # sign-extend eax to rax
	mov rsp, r8                          # switch to host stack
	pop rbx                              # restore rbx
	ret
ASM_END(setThreadArea64)

#endif // defined(__x86_64__) && defined(__linux__)

#if defined(__x86_64__) && defined(__APPLE__)

# bool installSelectors(TEB *teb)
ASM_GLOBAL(installSelectors, @function)
	mov ax, cs                              # fetch host code segment selector
	mov word ptr [rdi+TEB_HOST_CS_SEL], ax  # store host code segment selector
	mov ax, word ptr [rdi+TEB_DS_SEL]       # fetch data segment selector
	mov dx, word ptr [rdi+TEB_FS_SEL]       # fetch fs selector
	LJMP32 rdi                              # far jump into 32-bit code (sets cs)
	mov ds, ax                              # setup data segment
	mov es, ax                              # setup extra segment
	mov fs, dx                              # setup fs segment
	LJMP64 edi                              # far jump into 64-bit code
	mov rax, 1                              # return true
	ret
ASM_END(installSelectors)

#endif

.macro stubThunkX number
#if defined(__x86_64__)
#define STUB_THUNK_SYMBOL _Z9stubThunkILm\()\number\()EEvv
ASM_GLOBAL(STUB_THUNK_SYMBOL, @function)
#else
#define STUB_THUNK_SYMBOL _Z9stubThunkILj\()\number\()EEvv
ASM_GLOBAL(STUB_THUNK_SYMBOL, @function)
#endif
	pop eax
	push \number
	push eax
	jmp SYMBOL_NAME(thunk_entry_stubBase)
ASM_END(STUB_THUNK_SYMBOL)
.endm

.code32
stubThunkX 0
stubThunkX 1
stubThunkX 2
stubThunkX 3
stubThunkX 4
stubThunkX 5
stubThunkX 6
stubThunkX 7
stubThunkX 8
stubThunkX 9
stubThunkX 10
stubThunkX 11
stubThunkX 12
stubThunkX 13
stubThunkX 14
stubThunkX 15
stubThunkX 16
stubThunkX 17
stubThunkX 18
stubThunkX 19
stubThunkX 20
stubThunkX 21
stubThunkX 22
stubThunkX 23
stubThunkX 24
stubThunkX 25
stubThunkX 26
stubThunkX 27
stubThunkX 28
stubThunkX 29
stubThunkX 30
stubThunkX 31
stubThunkX 32
stubThunkX 33
stubThunkX 34
stubThunkX 35
stubThunkX 36
stubThunkX 37
stubThunkX 38
stubThunkX 39
stubThunkX 40
stubThunkX 41
stubThunkX 42
stubThunkX 43
stubThunkX 44
stubThunkX 45
stubThunkX 46
stubThunkX 47
stubThunkX 48
stubThunkX 49
stubThunkX 50
stubThunkX 51
stubThunkX 52
stubThunkX 53
stubThunkX 54
stubThunkX 55
stubThunkX 56
stubThunkX 57
stubThunkX 58
stubThunkX 59
stubThunkX 60
stubThunkX 61
stubThunkX 62
stubThunkX 63
stubThunkX 64
stubThunkX 65
stubThunkX 66
stubThunkX 67
stubThunkX 68
stubThunkX 69
stubThunkX 70
stubThunkX 71
stubThunkX 72
stubThunkX 73
stubThunkX 74
stubThunkX 75
stubThunkX 76
stubThunkX 77
stubThunkX 78
stubThunkX 79
stubThunkX 80
stubThunkX 81
stubThunkX 82
stubThunkX 83
stubThunkX 84
stubThunkX 85
stubThunkX 86
stubThunkX 87
stubThunkX 88
stubThunkX 89
stubThunkX 90
stubThunkX 91
stubThunkX 92
stubThunkX 93
stubThunkX 94
stubThunkX 95
stubThunkX 96
stubThunkX 97
stubThunkX 98
stubThunkX 99
stubThunkX 100
stubThunkX 101
stubThunkX 102
stubThunkX 103
stubThunkX 104
stubThunkX 105
stubThunkX 106
stubThunkX 107
stubThunkX 108
stubThunkX 109
stubThunkX 110
stubThunkX 111
stubThunkX 112
stubThunkX 113
stubThunkX 114
stubThunkX 115
stubThunkX 116
stubThunkX 117
stubThunkX 118
stubThunkX 119
stubThunkX 120
stubThunkX 121
stubThunkX 122
stubThunkX 123
stubThunkX 124
stubThunkX 125
stubThunkX 126
stubThunkX 127
stubThunkX 128
stubThunkX 129
stubThunkX 130
stubThunkX 131
stubThunkX 132
stubThunkX 133
stubThunkX 134
stubThunkX 135
stubThunkX 136
stubThunkX 137
stubThunkX 138
stubThunkX 139
stubThunkX 140
stubThunkX 141
stubThunkX 142
stubThunkX 143
stubThunkX 144
stubThunkX 145
stubThunkX 146
stubThunkX 147
stubThunkX 148
stubThunkX 149
stubThunkX 150
stubThunkX 151
stubThunkX 152
stubThunkX 153
stubThunkX 154
stubThunkX 155
stubThunkX 156
stubThunkX 157
stubThunkX 158
stubThunkX 159
stubThunkX 160
stubThunkX 161
stubThunkX 162
stubThunkX 163
stubThunkX 164
stubThunkX 165
stubThunkX 166
stubThunkX 167
stubThunkX 168
stubThunkX 169
stubThunkX 170
stubThunkX 171
stubThunkX 172
stubThunkX 173
stubThunkX 174
stubThunkX 175
stubThunkX 176
stubThunkX 177
stubThunkX 178
stubThunkX 179
stubThunkX 180
stubThunkX 181
stubThunkX 182
stubThunkX 183
stubThunkX 184
stubThunkX 185
stubThunkX 186
stubThunkX 187
stubThunkX 188
stubThunkX 189
stubThunkX 190
stubThunkX 191
stubThunkX 192
stubThunkX 193
stubThunkX 194
stubThunkX 195
stubThunkX 196
stubThunkX 197
stubThunkX 198
stubThunkX 199
stubThunkX 200
stubThunkX 201
stubThunkX 202
stubThunkX 203
stubThunkX 204
stubThunkX 205
stubThunkX 206
stubThunkX 207
stubThunkX 208
stubThunkX 209
stubThunkX 210
stubThunkX 211
stubThunkX 212
stubThunkX 213
stubThunkX 214
stubThunkX 215
stubThunkX 216
stubThunkX 217
stubThunkX 218
stubThunkX 219
stubThunkX 220
stubThunkX 221
stubThunkX 222
stubThunkX 223
stubThunkX 224
stubThunkX 225
stubThunkX 226
stubThunkX 227
stubThunkX 228
stubThunkX 229
stubThunkX 230
stubThunkX 231
stubThunkX 232
stubThunkX 233
stubThunkX 234
stubThunkX 235
stubThunkX 236
stubThunkX 237
stubThunkX 238
stubThunkX 239
stubThunkX 240
stubThunkX 241
stubThunkX 242
stubThunkX 243
stubThunkX 244
stubThunkX 245
stubThunkX 246
stubThunkX 247
stubThunkX 248
stubThunkX 249
stubThunkX 250
stubThunkX 251
stubThunkX 252
stubThunkX 253
stubThunkX 254
stubThunkX 255
stubThunkX 256
