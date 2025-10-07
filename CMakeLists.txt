cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_FLAGS_INIT "-m32")
set(CMAKE_CXX_FLAGS_INIT "-m32")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-m32")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-m32")

project(wibo LANGUAGES C CXX)

set(WIBO_VERSION "" CACHE STRING "Version string for the wibo binary; if empty, attempts to use git describe")

if(NOT "${WIBO_VERSION}" STREQUAL "")
    set(WIBO_VERSION_STRING "${WIBO_VERSION}")
elseif(DEFINED ENV{WIBO_VERSION} AND NOT "$ENV{WIBO_VERSION}" STREQUAL "")
    set(WIBO_VERSION_STRING "$ENV{WIBO_VERSION}")
else()
    find_package(Git QUIET)
    if(GIT_FOUND)
        execute_process(
            COMMAND ${GIT_EXECUTABLE} describe --tags --dirty --always
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            RESULT_VARIABLE WIBO_GIT_DESCRIBE_RESULT
            OUTPUT_VARIABLE WIBO_GIT_DESCRIBE_OUTPUT
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        if(WIBO_GIT_DESCRIBE_RESULT EQUAL 0 AND NOT "${WIBO_GIT_DESCRIBE_OUTPUT}" STREQUAL "")
            set(WIBO_VERSION_STRING "${WIBO_GIT_DESCRIBE_OUTPUT}")
        endif()
    endif()
endif()

if(NOT DEFINED WIBO_VERSION_STRING OR "${WIBO_VERSION_STRING}" STREQUAL "")
    set(WIBO_VERSION_STRING "unknown")
endif()

set(WIBO_GENERATED_HEADER_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${WIBO_GENERATED_HEADER_DIR})
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/version_info.h.in
    ${WIBO_GENERATED_HEADER_DIR}/version_info.h
    @ONLY
)

option(WIBO_ENABLE_FIXTURE_TESTS "Enable Win32 fixture tests (requires i686-w64-mingw32)" ON)
option(WIBO_ENABLE_LIBURING "Enable liburing for asynchronous I/O" OFF)
set(WIBO_ENABLE_LTO "AUTO" CACHE STRING "Enable link-time optimization (LTO)")
set_property(CACHE WIBO_ENABLE_LTO PROPERTY STRINGS "AUTO" "ON" "OFF")

if (WIBO_ENABLE_LTO STREQUAL "AUTO")
    if (CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
        include(CheckIPOSupported)
        check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
        if (ipo_supported)
            message(STATUS "Enabling LTO")
            set(WIBO_ENABLE_LTO ON)
        else()
            message(STATUS "LTO not supported: ${ipo_error}")
            set(WIBO_ENABLE_LTO OFF)
        endif()
    else()
        message(STATUS "Disabling LTO")
        set(WIBO_ENABLE_LTO OFF)
    endif()
elseif (NOT (WIBO_ENABLE_LTO STREQUAL "ON" OR WIBO_ENABLE_LTO STREQUAL "OFF"))
    message(FATAL_ERROR "WIBO_ENABLE_LTO must be ON, OFF, or AUTO")
endif()
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ${WIBO_ENABLE_LTO})

# Fetch and configure mimalloc
set(MI_BUILD_SHARED OFF CACHE BOOL "Build shared library" FORCE)
set(MI_BUILD_STATIC OFF CACHE BOOL "Build static library" FORCE)
set(MI_BUILD_OBJECT ON CACHE BOOL "Build object library" FORCE)
set(MI_BUILD_TESTS OFF CACHE BOOL "Build test executables" FORCE)

include(FetchContent)
FetchContent_Declare(
    mimalloc
    GIT_REPOSITORY https://github.com/microsoft/mimalloc.git
    GIT_TAG        dfa50c37d951128b1e77167dd9291081aa88eea4  # v3.1.5
)
FetchContent_MakeAvailable(mimalloc)

# Disable `note: the alignment of '_Atomic long long int' fields changed in GCC 11.1`
target_compile_options(mimalloc-obj PRIVATE -Wno-psabi)

if (WIBO_ENABLE_LIBURING)
    FetchContent_Declare(
        liburing
        GIT_REPOSITORY https://github.com/axboe/liburing.git
        GIT_TAG        e907d6a342e80b70874f93abd440b92b8a40b7bc  # liburing-2.12
    )
    FetchContent_MakeAvailable(liburing)

    add_custom_command(
        OUTPUT  ${liburing_SOURCE_DIR}/config-host.h
                ${liburing_SOURCE_DIR}/src/include/liburing/compat.h
        COMMAND ${CMAKE_COMMAND} -E env
                CC=${CMAKE_C_COMPILER}
                CXX=${CMAKE_CXX_COMPILER}
                ./configure --prefix=${liburing_BINARY_DIR}
        WORKING_DIRECTORY ${liburing_SOURCE_DIR}
        DEPENDS ${liburing_SOURCE_DIR}/configure
        COMMENT "Running liburing configure"
        VERBATIM
    )
    add_library(liburing STATIC
        ${liburing_SOURCE_DIR}/config-host.h
        ${liburing_SOURCE_DIR}/src/nolibc.c
        ${liburing_SOURCE_DIR}/src/queue.c
        ${liburing_SOURCE_DIR}/src/register.c
        ${liburing_SOURCE_DIR}/src/setup.c
        ${liburing_SOURCE_DIR}/src/syscall.c
        ${liburing_SOURCE_DIR}/src/version.c
        ${liburing_SOURCE_DIR}/src/include/liburing/compat.h)
    target_compile_definitions(liburing PRIVATE _GNU_SOURCE _FILE_OFFSET_BITS=64 _TIME_BITS=64)
    target_compile_options(liburing PRIVATE -include config-host.h)
    target_include_directories(liburing PUBLIC ${liburing_SOURCE_DIR}/src/include)
    target_include_directories(liburing PRIVATE ${liburing_SOURCE_DIR})
endif()

add_executable(wibo
    dll/advapi32.cpp
    dll/advapi32/processthreadsapi.cpp
    dll/advapi32/securitybaseapi.cpp
    dll/advapi32/winbase.cpp
    dll/advapi32/wincrypt.cpp
    dll/advapi32/winreg.cpp
    dll/bcrypt.cpp
    dll/crt.cpp
    dll/kernel32.cpp
    dll/kernel32/debugapi.cpp
    dll/kernel32/errhandlingapi.cpp
    dll/kernel32/fibersapi.cpp
    dll/kernel32/fileapi.cpp
    dll/kernel32/handleapi.cpp
    dll/kernel32/heapapi.cpp
    dll/kernel32/interlockedapi.cpp
    dll/kernel32/ioapiset.cpp
    dll/kernel32/libloaderapi.cpp
    dll/kernel32/namedpipeapi.cpp
    dll/kernel32/memoryapi.cpp
    dll/kernel32/processenv.cpp
    dll/kernel32/processthreadsapi.cpp
    dll/kernel32/profileapi.cpp
    dll/kernel32/stringapiset.cpp
    dll/kernel32/synchapi.cpp
    dll/kernel32/sysinfoapi.cpp
    dll/kernel32/timezoneapi.cpp
    dll/kernel32/winbase.cpp
    dll/kernel32/wincon.cpp
    dll/kernel32/winnls.cpp
    dll/kernel32/winnt.cpp
    dll/kernel32/wow64apiset.cpp
    dll/lmgr.cpp
    dll/mscoree.cpp
    dll/msvcrt.cpp
    dll/ntdll.cpp
    dll/rpcrt4.cpp
    dll/ole32.cpp
    dll/user32.cpp
    dll/vcruntime.cpp
    dll/version.cpp
    src/access.cpp
    src/async_io.cpp
    src/context.cpp
    src/errors.cpp
    src/files.cpp
    src/handles.cpp
    src/loader.cpp
    src/main.cpp
    src/modules.cpp
    src/processes.cpp
    src/resources.cpp
    src/strutil.cpp
)
target_compile_definitions(wibo PRIVATE _GNU_SOURCE _FILE_OFFSET_BITS=64 _TIME_BITS=64)
target_compile_features(wibo PRIVATE cxx_std_20)
target_compile_options(wibo PRIVATE -Wall -Wextra -fno-pie -maccumulate-outgoing-args)
target_include_directories(wibo PRIVATE dll src ${WIBO_GENERATED_HEADER_DIR})
target_link_libraries(wibo PRIVATE mimalloc-obj)
target_link_options(wibo PRIVATE -no-pie)
if (WIBO_ENABLE_LIBURING)
    target_compile_definitions(wibo PRIVATE WIBO_ENABLE_LIBURING=1)
    target_link_libraries(wibo PRIVATE liburing)
    target_sources(wibo PRIVATE src/async_io_uring.cpp)
else()
    target_compile_definitions(wibo PRIVATE WIBO_ENABLE_LIBURING=0)
endif()
install(TARGETS wibo DESTINATION bin)

if (WIBO_ENABLE_FIXTURE_TESTS)
    include(CTest)

    find_program(WIBO_MINGW_CC i686-w64-mingw32-gcc)
    find_program(WIBO_MINGW_WINDRES i686-w64-mingw32-windres)

    set(WIBO_HAVE_MINGW_TOOLCHAIN FALSE)
    if(WIBO_MINGW_CC AND WIBO_MINGW_WINDRES)
        set(WIBO_HAVE_MINGW_TOOLCHAIN TRUE)
    endif()

    if(NOT WIBO_HAVE_MINGW_TOOLCHAIN)
        message(WARNING "MinGW toolchain not found; skipping fixture tests")
    else()
        set(WIBO_TEST_BIN_DIR ${CMAKE_CURRENT_BINARY_DIR}/test)
        file(MAKE_DIRECTORY ${WIBO_TEST_BIN_DIR})

        function(wibo_add_fixture_dll)
            set(options)
            set(oneValueArgs NAME)
            set(multiValueArgs SOURCES COMPILE_OPTIONS DEPENDS)
            cmake_parse_arguments(PARSE_ARGV 0 fixture "${options}" "${oneValueArgs}" "${multiValueArgs}")

            set(fixture_OUTPUT ${WIBO_TEST_BIN_DIR}/${fixture_NAME}.dll)
            add_custom_command(
                OUTPUT ${fixture_OUTPUT}
                COMMAND ${WIBO_MINGW_CC} -Wall -Wextra -O2 -shared
                        -I${CMAKE_CURRENT_SOURCE_DIR}/test
                        -o ${fixture_OUTPUT}
                        ${fixture_SOURCES}
                        ${fixture_COMPILE_OPTIONS}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                DEPENDS ${fixture_SOURCES} ${fixture_DEPENDS})
            list(APPEND WIBO_TEST_FIXTURES ${fixture_OUTPUT})
            set(WIBO_TEST_FIXTURES ${WIBO_TEST_FIXTURES} PARENT_SCOPE)
        endfunction(wibo_add_fixture_dll)

        function(wibo_add_fixture_bin)
            set(options)
            set(oneValueArgs NAME)
            set(multiValueArgs SOURCES COMPILE_OPTIONS DEPENDS)
            cmake_parse_arguments(PARSE_ARGV 0 fixture "${options}" "${oneValueArgs}" "${multiValueArgs}")

            set(fixture_OUTPUT ${WIBO_TEST_BIN_DIR}/${fixture_NAME}.exe)
            add_custom_command(
                OUTPUT ${fixture_OUTPUT}
                COMMAND ${WIBO_MINGW_CC} -Wall -Wextra -O2
                        -I${CMAKE_CURRENT_SOURCE_DIR}/test
                        -o ${fixture_OUTPUT}
                        ${fixture_SOURCES}
                        ${fixture_COMPILE_OPTIONS}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                DEPENDS ${fixture_SOURCES} ${fixture_DEPENDS})
            list(APPEND WIBO_TEST_FIXTURES ${fixture_OUTPUT})
            set(WIBO_TEST_FIXTURES ${WIBO_TEST_FIXTURES} PARENT_SCOPE)

            add_test(NAME wibo.${fixture_NAME}
                COMMAND $<TARGET_FILE:wibo> ${fixture_OUTPUT})
            set_tests_properties(wibo.${fixture_NAME} PROPERTIES
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test
                DEPENDS wibo.build_fixtures)
        endfunction(wibo_add_fixture_bin)

        # Define fixture tests
        wibo_add_fixture_bin(NAME test_external_dll SOURCES test/test_external_dll.c)
        wibo_add_fixture_bin(NAME test_dll_attach_failure SOURCES test/test_dll_attach_failure.c)
        wibo_add_fixture_bin(NAME test_thread_notifications SOURCES test/test_thread_notifications.c)
        wibo_add_fixture_bin(NAME test_bcrypt SOURCES test/test_bcrypt.c COMPILE_OPTIONS -lbcrypt)
        wibo_add_fixture_bin(NAME test_resources SOURCES test/test_resources.c ${WIBO_TEST_BIN_DIR}/test_resources_res.o COMPILE_OPTIONS -lversion)
        wibo_add_fixture_bin(NAME test_threading SOURCES test/test_threading.c)
        wibo_add_fixture_bin(NAME test_handleapi SOURCES test/test_handleapi.c)
        wibo_add_fixture_bin(NAME test_findfile SOURCES test/test_findfile.c)
        wibo_add_fixture_bin(NAME test_synchapi SOURCES test/test_synchapi.c)
        wibo_add_fixture_bin(NAME test_processes SOURCES test/test_processes.c)
        wibo_add_fixture_bin(NAME test_heap SOURCES test/test_heap.c)
        wibo_add_fixture_bin(NAME test_actctx SOURCES test/test_actctx.c)
        wibo_add_fixture_bin(NAME test_overlapped_io SOURCES test/test_overlapped_io.c)
        wibo_add_fixture_bin(NAME test_time SOURCES test/test_time.c)
        wibo_add_fixture_bin(NAME test_virtualalloc SOURCES test/test_virtualalloc.c)
        wibo_add_fixture_bin(NAME test_virtualquery SOURCES test/test_virtualquery.c)
        wibo_add_fixture_bin(NAME test_rtl SOURCES test/test_rtl.c)
        wibo_add_fixture_bin(NAME test_ntquery SOURCES test/test_ntquery.c)
        wibo_add_fixture_bin(NAME test_ntreadfile SOURCES test/test_ntreadfile.c)
        wibo_add_fixture_bin(NAME test_pipe_io SOURCES test/test_pipe_io.c)
        wibo_add_fixture_bin(NAME test_sysdir SOURCES test/test_sysdir.c)

        # DLLs for fixture tests
        wibo_add_fixture_dll(NAME external_exports SOURCES test/external_exports.c)
        wibo_add_fixture_dll(NAME dll_attach_failure SOURCES test/dll_attach_failure.c)
        wibo_add_fixture_dll(NAME thread_notifications SOURCES test/thread_notifications.c)

        # Resources for test_resources
        add_custom_command(
            OUTPUT ${WIBO_TEST_BIN_DIR}/test_resources_res.o
            COMMAND ${WIBO_MINGW_WINDRES}
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/test_resources.rc
                    -O coff -o test_resources_res.o
            WORKING_DIRECTORY ${WIBO_TEST_BIN_DIR}
            DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/test/test_resources.rc)

        add_custom_target(wibo_test_fixtures DEPENDS ${WIBO_TEST_FIXTURES})

        if(CMAKE_CONFIGURATION_TYPES)
            set(_wibo_fixture_build_command
                ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --config $<CONFIG> --target wibo_test_fixtures)
        else()
            set(_wibo_fixture_build_command
                ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target wibo_test_fixtures)
        endif()

        add_test(NAME wibo.build_fixtures COMMAND ${_wibo_fixture_build_command})
    endif()
endif()
