cmake_minimum_required(VERSION 3.16)
project(checkmd5-qt VERSION 0.100 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Default to an optimized build when the user hasn't chosen a build type.
# Optimization is only applied per build type (Release enables IPO/-O3), so
# without this an unspecified build silently produces an unoptimized (-O0)
# binary. A Debug build is still honored when explicitly requested.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Find Qt6
find_package(Qt6 REQUIRED COMPONENTS Core)

# Enable automatic MOC processing
set(CMAKE_AUTOMOC ON)

# Add executable
add_executable(checkmd5-qt
    main.cpp
    checkmd5.cpp
    checkmd5.h
    md5.cpp
    md5.h
    version.h
)

# Link Qt libraries
target_link_libraries(checkmd5-qt Qt6::Core)

target_compile_options(checkmd5-qt PRIVATE
    -Wall
    -Wextra
)

include(CheckIPOSupported)
check_ipo_supported(RESULT IPO_SUPPORTED OUTPUT IPO_ERROR)
if(IPO_SUPPORTED)
    set_property(TARGET checkmd5-qt PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
endif()

# Install target
install(TARGETS checkmd5-qt
    RUNTIME DESTINATION bin
)

# Install man page
install(FILES checkmd5.1
    DESTINATION share/man/man1
    RENAME checkmd5-qt.1
)

enable_testing()

set(TEST_FIXTURE_DIR ${CMAKE_CURRENT_BINARY_DIR}/test-fixtures)
file(MAKE_DIRECTORY ${TEST_FIXTURE_DIR})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/test_data.txt DESTINATION ${TEST_FIXTURE_DIR})
file(WRITE ${TEST_FIXTURE_DIR}/good.md5 "5d41402abc4b2a76b9719d911017c592  test_data.txt\n")
file(WRITE ${TEST_FIXTURE_DIR}/mismatch.md5 "00000000000000000000000000000000  test_data.txt\n")
file(WRITE ${TEST_FIXTURE_DIR}/missing.md5 "d41d8cd98f00b204e9800998ecf8427e  missing-file.txt\n")
file(WRITE ${TEST_FIXTURE_DIR}/malformed.md5 "not-an-md5 line\n")
file(MAKE_DIRECTORY ${TEST_FIXTURE_DIR}/lists/data)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/test_data.txt DESTINATION ${TEST_FIXTURE_DIR}/lists/data)
file(WRITE ${TEST_FIXTURE_DIR}/lists/relative.md5 "5d41402abc4b2a76b9719d911017c592  data/test_data.txt\n")

set(TEST_DRIVER ${CMAKE_CURRENT_BINARY_DIR}/run-checkmd5-test.cmake)
file(WRITE ${TEST_DRIVER} [=[
separate_arguments(parsed_args UNIX_COMMAND "${CHECKMD5_ARGS}")

execute_process(
    COMMAND "${CHECKMD5_BIN}" ${parsed_args}
    WORKING_DIRECTORY "${TEST_WORKDIR}"
    RESULT_VARIABLE actual_exit
    OUTPUT_VARIABLE actual_stdout
    ERROR_VARIABLE actual_stderr
)

if(NOT actual_exit EQUAL EXPECTED_EXIT)
    message(FATAL_ERROR "Expected exit ${EXPECTED_EXIT}, got ${actual_exit}\nstdout:\n${actual_stdout}\nstderr:\n${actual_stderr}")
endif()

if(CHECKMD5_ARGS MATCHES "--machine")
    if(actual_stdout STREQUAL "")
        message(FATAL_ERROR "--machine produced no stdout")
    endif()
    if(actual_stderr MATCHES "(^|\n)[0-9]+(\\.[0-9]+)?%(\n|$)")
        message(FATAL_ERROR "--machine progress was written to stderr:\n${actual_stderr}")
    endif()
endif()
]=])

function(add_checkmd5_test name workdir expected_exit)
    list(JOIN ARGN " " checkmd5_args)
    add_test(NAME ${name}
        COMMAND ${CMAKE_COMMAND}
            -D "CHECKMD5_BIN=$<TARGET_FILE:checkmd5-qt>"
            -D "TEST_WORKDIR=${workdir}"
            -D "EXPECTED_EXIT=${expected_exit}"
            -D "CHECKMD5_ARGS=${checkmd5_args}"
            -P ${TEST_DRIVER})
endfunction()

add_checkmd5_test(checkmd5_success ${TEST_FIXTURE_DIR} 0 good.md5)
add_checkmd5_test(checkmd5_relative_path ${TEST_FIXTURE_DIR}/lists 0 relative.md5)
add_checkmd5_test(checkmd5_machine_stdout ${TEST_FIXTURE_DIR} 0 --machine good.md5)
add_checkmd5_test(checkmd5_machine_mismatch ${TEST_FIXTURE_DIR} 1 --machine mismatch.md5)
add_checkmd5_test(checkmd5_parallel_success ${TEST_FIXTURE_DIR} 0 --jobs=2 good.md5)
add_checkmd5_test(checkmd5_mismatch ${TEST_FIXTURE_DIR} 1 mismatch.md5)
add_checkmd5_test(checkmd5_missing_target ${TEST_FIXTURE_DIR} 3 missing.md5)
add_checkmd5_test(checkmd5_malformed_list ${TEST_FIXTURE_DIR} 3 malformed.md5)
