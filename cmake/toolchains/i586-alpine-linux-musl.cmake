# Toolchain file for static 32-bit Linux builds with Clang and musl
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR i686)

# Specify the compiler
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_ASM_COMPILER clang)
set(CMAKE_LINKER_TYPE LLD)

# Set the target triple for cross-compilation
set(TARGET i586-alpine-linux-musl)
set(CMAKE_C_COMPILER_TARGET ${TARGET})
set(CMAKE_CXX_COMPILER_TARGET ${TARGET})
set(CMAKE_ASM_COMPILER_TARGET ${TARGET})

# Force 32-bit compilation
set(CMAKE_C_FLAGS_INIT "-static")
set(CMAKE_CXX_FLAGS_INIT "-static")
set(CMAKE_ASM_FLAGS_INIT "-static")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-fuse-ld=lld -static")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-fuse-ld=lld -static")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "-fuse-ld=lld -static")

# Search for programs in the build host directories
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# Search for libraries and headers in the target directories
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Inform mimalloc that we are using musl libc
set(MI_LIBC_MUSL ON)
