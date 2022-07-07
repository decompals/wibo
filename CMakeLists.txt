cmake_minimum_required(VERSION 3.10)
project(wibo LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(Filesystem REQUIRED COMPONENTS Final Experimental)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32 -Wall")
add_executable(wibo
    advapi32.cpp
    files.cpp
    kernel32.cpp
    lmgr.cpp
    loader.cpp
    main.cpp
    ole32.cpp
    user32.cpp
    version.cpp
    )
target_link_libraries(wibo PRIVATE std::filesystem)
install(TARGETS wibo DESTINATION bin)
