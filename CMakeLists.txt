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

# Disable mimalloc tests
set(MI_BUILD_TESTS OFF CACHE BOOL "Build test executables" FORCE)

include(FetchContent)
FetchContent_Declare(
    mimalloc
    GIT_REPOSITORY https://github.com/microsoft/mimalloc.git
    GIT_TAG        dfa50c37d951128b1e77167dd9291081aa88eea4  # v3.1.5
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
    dll/rpcrt4.cpp
    dll/ole32.cpp
    dll/user32.cpp
    dll/vcruntime.cpp
    dll/version.cpp
    errors.cpp
    files.cpp
    handles.cpp
    loader.cpp
    resources.cpp
    module_registry.cpp
    main.cpp
    processes.cpp
    strutil.cpp
)
target_link_libraries(wibo PRIVATE std::filesystem mimalloc-static)
install(TARGETS wibo DESTINATION bin)

include(CTest)

if(BUILD_TESTING)
    find_program(WIBO_MINGW_CC i686-w64-mingw32-gcc)
    find_program(WIBO_MINGW_WINDRES i686-w64-mingw32-windres)

    set(WIBO_HAVE_MINGW_TOOLCHAIN FALSE)
    if(WIBO_MINGW_CC AND WIBO_MINGW_WINDRES)
        set(WIBO_HAVE_MINGW_TOOLCHAIN TRUE)
    endif()

    option(WIBO_ENABLE_FIXTURE_TESTS "Build and run Windows fixture binaries through wibo" ${WIBO_HAVE_MINGW_TOOLCHAIN})

    if(WIBO_ENABLE_FIXTURE_TESTS)
        if(NOT WIBO_HAVE_MINGW_TOOLCHAIN)
            message(WARNING "MinGW toolchain not found; skipping fixture tests")
        else()
            set(WIBO_TEST_BIN_DIR ${CMAKE_CURRENT_BINARY_DIR}/test)
            file(MAKE_DIRECTORY ${WIBO_TEST_BIN_DIR})

            add_custom_command(
                OUTPUT ${WIBO_TEST_BIN_DIR}/external_exports.dll
                COMMAND ${WIBO_MINGW_CC} -Wall -Wextra -O2 -shared
                        -o external_exports.dll
                        ${CMAKE_CURRENT_SOURCE_DIR}/test/external_exports.c
                WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
                DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/test/external_exports.c)

            add_custom_command(
                OUTPUT ${WIBO_TEST_BIN_DIR}/test_external_dll.exe
                COMMAND ${WIBO_MINGW_CC} -Wall -Wextra -O2
                        -I${CMAKE_CURRENT_SOURCE_DIR}/test
                        -o test_external_dll.exe
                        ${CMAKE_CURRENT_SOURCE_DIR}/test/test_external_dll.c
                WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
                DEPENDS
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_external_dll.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_assert.h)

            add_custom_command(
                OUTPUT ${WIBO_TEST_BIN_DIR}/test_bcrypt.exe
                COMMAND ${WIBO_MINGW_CC} -Wall -Wextra -O2
                        -I${CMAKE_CURRENT_SOURCE_DIR}/test
                        -o test_bcrypt.exe
                        ${CMAKE_CURRENT_SOURCE_DIR}/test/test_bcrypt.c
                        -lbcrypt
                WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
                DEPENDS
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_bcrypt.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_assert.h)

            add_custom_command(
                OUTPUT ${WIBO_TEST_BIN_DIR}/test_resources_res.o
                COMMAND ${WIBO_MINGW_WINDRES}
                        ${CMAKE_CURRENT_SOURCE_DIR}/test/test_resources.rc
                        -O coff -o test_resources_res.o
                WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
                DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/test/test_resources.rc)

            add_custom_command(
                OUTPUT ${WIBO_TEST_BIN_DIR}/test_resources.exe
                COMMAND ${WIBO_MINGW_CC} -Wall -Wextra -O2
                        -I${CMAKE_CURRENT_SOURCE_DIR}/test
                        -o test_resources.exe
                        ${CMAKE_CURRENT_SOURCE_DIR}/test/test_resources.c
                        test_resources_res.o -lversion
                WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
                DEPENDS
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_resources.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_assert.h
                    ${WIBO_TEST_BIN_DIR}/test_resources_res.o)

            add_custom_command(
                OUTPUT ${WIBO_TEST_BIN_DIR}/test_threading.exe
                COMMAND ${WIBO_MINGW_CC} -Wall -Wextra -O2
                        -I${CMAKE_CURRENT_SOURCE_DIR}/test
                        -o test_threading.exe
                        ${CMAKE_CURRENT_SOURCE_DIR}/test/test_threading.c
                WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
                DEPENDS
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_threading.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_assert.h)

            add_custom_command(
                OUTPUT ${WIBO_TEST_BIN_DIR}/test_heap.exe
                COMMAND ${WIBO_MINGW_CC} -Wall -Wextra -O2
                        -I${CMAKE_CURRENT_SOURCE_DIR}/test
                        -o test_heap.exe
                        ${CMAKE_CURRENT_SOURCE_DIR}/test/test_heap.c
                WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
                DEPENDS
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_heap.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_assert.h)

            add_custom_command(
                OUTPUT ${WIBO_TEST_BIN_DIR}/test_overlapped_io.exe
                COMMAND ${WIBO_MINGW_CC} -Wall -Wextra -O2
                        -I${CMAKE_CURRENT_SOURCE_DIR}/test
                        -o test_overlapped_io.exe
                        ${CMAKE_CURRENT_SOURCE_DIR}/test/test_overlapped_io.c
                WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
                DEPENDS
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_overlapped_io.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_assert.h)

            add_custom_command(
                OUTPUT ${WIBO_TEST_BIN_DIR}/test_time.exe
                COMMAND ${WIBO_MINGW_CC} -Wall -Wextra -O2
                        -I${CMAKE_CURRENT_SOURCE_DIR}/test
                        -o test_time.exe
                        ${CMAKE_CURRENT_SOURCE_DIR}/test/test_time.c
                WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
                DEPENDS
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_time.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_assert.h)

            add_custom_command(
                OUTPUT ${WIBO_TEST_BIN_DIR}/test_virtualalloc.exe
                COMMAND ${WIBO_MINGW_CC} -Wall -Wextra -O2
                        -I${CMAKE_CURRENT_SOURCE_DIR}/test
                        -o test_virtualalloc.exe
                        ${CMAKE_CURRENT_SOURCE_DIR}/test/test_virtualalloc.c
                WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
                DEPENDS
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_virtualalloc.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_assert.h)

            add_custom_target(wibo_test_fixtures
                DEPENDS
                    ${WIBO_TEST_BIN_DIR}/external_exports.dll
                    ${WIBO_TEST_BIN_DIR}/test_external_dll.exe
                    ${WIBO_TEST_BIN_DIR}/test_bcrypt.exe
                    ${WIBO_TEST_BIN_DIR}/test_resources.exe
                    ${WIBO_TEST_BIN_DIR}/test_threading.exe
                    ${WIBO_TEST_BIN_DIR}/test_heap.exe
                    ${WIBO_TEST_BIN_DIR}/test_overlapped_io.exe
                    ${WIBO_TEST_BIN_DIR}/test_time.exe
                    ${WIBO_TEST_BIN_DIR}/test_virtualalloc.exe)

            if(CMAKE_CONFIGURATION_TYPES)
                set(_wibo_fixture_build_command
                    ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --config $<CONFIG> --target wibo_test_fixtures)
            else()
                set(_wibo_fixture_build_command
                    ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target wibo_test_fixtures)
            endif()

            add_test(NAME wibo.build_fixtures COMMAND ${_wibo_fixture_build_command})

            add_test(NAME wibo.test_external_dll
                COMMAND $<TARGET_FILE:wibo> ${WIBO_TEST_BIN_DIR}/test_external_dll.exe)
            set_tests_properties(wibo.test_external_dll PROPERTIES
                WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
                DEPENDS wibo.build_fixtures)

            add_test(NAME wibo.test_bcrypt
                COMMAND $<TARGET_FILE:wibo> ${WIBO_TEST_BIN_DIR}/test_bcrypt.exe)
            set_tests_properties(wibo.test_bcrypt PROPERTIES
                WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
                DEPENDS wibo.build_fixtures)

            add_test(NAME wibo.test_resources
                COMMAND $<TARGET_FILE:wibo> ${WIBO_TEST_BIN_DIR}/test_resources.exe)
            set_tests_properties(wibo.test_resources PROPERTIES
                WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
                DEPENDS wibo.build_fixtures)

            add_test(NAME wibo.test_threading
                COMMAND $<TARGET_FILE:wibo> ${WIBO_TEST_BIN_DIR}/test_threading.exe)
            set_tests_properties(wibo.test_threading PROPERTIES
                WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
                DEPENDS wibo.build_fixtures)

            add_test(NAME wibo.test_heap
                COMMAND $<TARGET_FILE:wibo> ${WIBO_TEST_BIN_DIR}/test_heap.exe)
            set_tests_properties(wibo.test_heap PROPERTIES
                WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
                DEPENDS wibo.build_fixtures)

            add_test(NAME wibo.test_overlapped_io
                COMMAND $<TARGET_FILE:wibo> ${WIBO_TEST_BIN_DIR}/test_overlapped_io.exe)
            set_tests_properties(wibo.test_overlapped_io PROPERTIES
                WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
                DEPENDS wibo.build_fixtures)

            add_test(NAME wibo.test_time
                COMMAND $<TARGET_FILE:wibo> ${WIBO_TEST_BIN_DIR}/test_time.exe)
            set_tests_properties(wibo.test_time PROPERTIES
                WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
                DEPENDS wibo.build_fixtures)

            add_test(NAME wibo.test_virtualalloc
                COMMAND $<TARGET_FILE:wibo> ${WIBO_TEST_BIN_DIR}/test_virtualalloc.exe)
            set_tests_properties(wibo.test_virtualalloc PROPERTIES
                WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
                DEPENDS wibo.build_fixtures)
        endif()
    endif()
endif()
