#pragma once

#define TEB_SELF 0x18	 // Self
#define TEB_FS_SEL 0xf98 // CurrentFsSelector
#define TEB_GS_SEL 0xf9a // CurrentGsSelector

#ifdef __i386__

#define TEB_SP 0xf9c // CurrentStackPointer

#endif // __i386__

#ifdef __x86_64__

#define TEB_SP 0xfa0	 // CurrentStackPointer
#define TEB_FSBASE 0xfa8 // HostFsBase
#define TEB_GSBASE 0xfb0 // HostGsBase

#ifdef __linux__
#define CS_32 0x23 // 32-bit code segment (Linux)
#define CS_64 0x33 // 64-bit code segment (Linux)
#define DS_32 0x2b // 32-bit data segment (Linux)
#elif defined(__APPLE__)
#define CS_64 0x2b // 64-bit code segment (macOS)
#else
#error "Unsupported platform"
#endif

#ifndef __USER_LABEL_PREFIX__
#define __USER_LABEL_PREFIX__
#endif

#define GLUE2_(a, b) a##b
#define GLUE(a, b) GLUE2_(a, b)
#define SYMBOL_NAME(name) GLUE(__USER_LABEL_PREFIX__, name)

#ifndef __ASSEMBLER__
#define STR_(S) #S
#define STR(S) STR_(S)
#define SYMBOL_NAME_STR_(name) STR(__USER_LABEL_PREFIX__) #name
#define SYMBOL_NAME_STR(name) SYMBOL_NAME_STR_(name)

#if __SIZEOF_POINTER__ == 8
#define ASM_SIZE_TYPE "quad"
#else
#define ASM_SIZE_TYPE "long"
#endif
#if __ELF__
#define ASM_RODATA_SECTION ".rodata"
#else
#define ASM_RODATA_SECTION ".section __TEXT, __const"
#endif

// clang-format off
#define INCLUDE_BIN(symbol, file)                                 \
    asm(ASM_RODATA_SECTION "\n"                                   \
        ".globl " SYMBOL_NAME_STR(symbol) "\n"                    \
        SYMBOL_NAME_STR(symbol) ":\n"                             \
        ".incbin \"" file "\"\n"                                  \
        ".globl " SYMBOL_NAME_STR(GLUE(symbol, End)) "\n"         \
        SYMBOL_NAME_STR(GLUE(symbol, End)) ":\n");                \
    extern "C" {                                                  \
        extern const uint8_t symbol[];                            \
        extern const uint8_t GLUE(symbol, End)[];                 \
    }
// clang-format on
#define INCLUDE_BIN_SIZE(symbol)                                                                                       \
	static_cast<std::size_t>(reinterpret_cast<std::uintptr_t>(&GLUE(symbol, End)) -                                    \
							 reinterpret_cast<std::uintptr_t>(&symbol))
#define INCLUDE_BIN_SPAN(symbol) std::span<const std::uint8_t>(symbol, INCLUDE_BIN_SIZE(symbol))
#endif

#endif
