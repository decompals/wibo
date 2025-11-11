#pragma once

#define TEB_SELF 0x18	 // Self
#define TEB_FS_SEL 0xf98 // CurrentFsSelector
#define TEB_GS_SEL 0xf9a // CurrentGsSelector

#ifdef __i386__

#define TEB_SP 0xf9c // CurrentStackPointer

#endif // __i386__

#ifdef __x86_64__

#define TEB_CS_SEL 0xf9c	   // CodeSelector
#define TEB_DS_SEL 0xf9e	   // DataSelector
#define TEB_SP 0xfa0		   // CurrentStackPointer
#define TEB_FSBASE 0xfa8	   // HostFsBase
#define TEB_GSBASE 0xfb0	   // HostGsBase
#define TEB_HAS_FSGSBASE 0xfb8 // HasFsGsBase
#define TEB_HOST_CS_SEL 0xfba  // HostCodeSelector

#endif

#if defined(__linux__)
#define GNU_ASSEMBLER 1
#elif defined(__clang__)
#define GNU_ASSEMBLER 0
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
#define ASM_RODATA_SECTION ".section .rodata"
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
