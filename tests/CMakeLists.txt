# Test Suite CMake Configuration
cmake_minimum_required(VERSION 3.20)

# Test executable
add_executable(ghost_tests
    test_suite.c
)

# Link with kernel and bootloader
target_link_libraries(ghost_tests
    PRIVATE
    ghost_kernel
    ghost_bootloader
)

# Include directories
target_include_directories(ghost_tests
    PRIVATE
    ${CMAKE_SOURCE_DIR}/kernel/src
    ${CMAKE_SOURCE_DIR}/bootloader
)

# Test-specific defines
target_compile_definitions(ghost_tests
    PRIVATE
    GHOST_TESTING
    $<$<STREQUAL:${TEST_TYPE},memory>:TEST_MEMORY_ONLY>
    $<$<STREQUAL:${TEST_TYPE},security>:TEST_SECURITY_ONLY>
    $<$<STREQUAL:${TEST_TYPE},boot>:TEST_BOOT_ONLY>
)

# Copy test executable to output directory
add_custom_command(TARGET ghost_tests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:ghost_tests>
        ${CMAKE_BINARY_DIR}/tests/
)
