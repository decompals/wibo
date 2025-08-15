cmake_minimum_required(VERSION 3.13)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING
        "Build type options: Debug Release RelWithDebInfo MinSizeRel" FORCE)
endif()

set(CMAKE_C_FLAGS_INIT "-m32")
set(CMAKE_CXX_FLAGS_INIT "-m32")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-m32")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-m32")

project(wibo LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fno-pie -no-pie -D_LARGEFILE64_SOURCE")

find_package(Filesystem REQUIRED)

include(FetchContent)
FetchContent_Declare(
    mimalloc
    GIT_REPOSITORY https://github.com/microsoft/mimalloc.git
    GIT_TAG        v3.1.5
)
FetchContent_MakeAvailable(mimalloc)

include_directories(.)
add_executable(wibo
    dll/advapi32.cpp
    dll/bcrypt.cpp
    dll/crt.cpp
    dll/kernel32.cpp
    dll/lmgr.cpp
    dll/mscoree.cpp
    dll/msvcrt.cpp
    dll/ntdll.cpp
    dll/ole32.cpp
    dll/user32.cpp
    dll/vcruntime.cpp
    dll/version.cpp
    files.cpp
    handles.cpp
    loader.cpp
    main.cpp
    processes.cpp
    strutil.cpp
)
target_link_libraries(wibo PRIVATE std::filesystem mimalloc-static)
install(TARGETS wibo DESTINATION bin)
