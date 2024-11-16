# GhostOS Root CMake Configuration
cmake_minimum_required(VERSION 3.20)

# Include our toolchain file before project() command
set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/config/toolchain.cmake")

# Set build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Initialize project
project(GhostOS C ASM)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include deployment configuration
include(${CMAKE_CURRENT_SOURCE_DIR}/config/deployment.cmake)

# Components
add_subdirectory(kernel)
add_subdirectory(bootloader)

# Tests
option(BUILD_TESTS "Build test suite" OFF)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Perform deployment checks
perform_deployment_checks()

# Create deployment package
create_deployment_package()
