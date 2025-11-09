# Toolchain file for 64-bit Linux builds with GCC
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Specify the compiler
set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_COMPILER g++)
set(CMAKE_ASM_COMPILER gcc)

# Set the target triple for cross-compilation
set(TARGET x86_64-linux-gnu)
set(CMAKE_C_COMPILER_TARGET ${TARGET})
set(CMAKE_CXX_COMPILER_TARGET ${TARGET})
set(CMAKE_ASM_COMPILER_TARGET ${TARGET})

# Force 64-bit compilation
set(CMAKE_C_FLAGS_INIT "-m64")
set(CMAKE_CXX_FLAGS_INIT "-m64")
set(CMAKE_ASM_FLAGS_INIT "-m64")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-m64")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-m64")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "-m64")

# Set library architecture
set(CMAKE_LIBRARY_ARCHITECTURE x86_64-linux-gnu)

# Search for programs in the build host directories
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# Search for libraries and headers in the target directories
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
