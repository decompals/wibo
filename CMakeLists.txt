cmake_minimum_required(VERSION 3.13)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING
        "Build type options: Debug Release RelWithDebInfo MinSizeRel" FORCE)
endif()

project(wibo LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(Filesystem REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32 -Wall")
include_directories(.)
add_executable(wibo
    dll/advapi32.cpp
    dll/bcrypt.cpp
    dll/crt.cpp
    dll/kernel32.cpp
    dll/lmgr.cpp
    dll/ntdll.cpp
    dll/ole32.cpp
    dll/user32.cpp
    dll/vcruntime.cpp
    dll/version.cpp
    dll/msvcrt.cpp
    files.cpp
    processes.cpp
    handles.cpp
    loader.cpp
    main.cpp
)
target_link_libraries(wibo PRIVATE std::filesystem)
install(TARGETS wibo DESTINATION bin)
