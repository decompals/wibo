cmake_minimum_required(VERSION 3.13)
project(wibo LANGUAGES CXX)
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
target_link_libraries(wibo PRIVATE stdc++fs)
install(PROGRAMS wibo DESTINATION bin)
