# GhostOS ARM Toolchain Configuration
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR ARM)

# Get the path to our tools directory
get_filename_component(TOOLCHAIN_DIR "${CMAKE_CURRENT_LIST_DIR}/../tools" ABSOLUTE)

# Find the GCC toolchain directory
file(GLOB GCC_DIR "${TOOLCHAIN_DIR}/gcc-arm-none-eabi-*")
if(NOT GCC_DIR)
    message(FATAL_ERROR "ARM GCC toolchain not found in ${TOOLCHAIN_DIR}")
endif()

# Set the toolchain paths
set(TOOLCHAIN_BIN_DIR "${GCC_DIR}/bin")
set(TOOLCHAIN_PREFIX "arm-none-eabi-")
set(TOOLCHAIN_SYSROOT "${GCC_DIR}/arm-none-eabi")

# Set the compilers
set(CMAKE_C_COMPILER "${TOOLCHAIN_BIN_DIR}/${TOOLCHAIN_PREFIX}gcc.exe" CACHE FILEPATH "C compiler")
set(CMAKE_CXX_COMPILER "${TOOLCHAIN_BIN_DIR}/${TOOLCHAIN_PREFIX}g++.exe" CACHE FILEPATH "C++ compiler")
set(CMAKE_ASM_COMPILER "${TOOLCHAIN_BIN_DIR}/${TOOLCHAIN_PREFIX}gcc.exe" CACHE FILEPATH "ASM compiler")
set(CMAKE_OBJCOPY "${TOOLCHAIN_BIN_DIR}/${TOOLCHAIN_PREFIX}objcopy.exe" CACHE FILEPATH "objcopy tool")
set(CMAKE_SIZE "${TOOLCHAIN_BIN_DIR}/${TOOLCHAIN_PREFIX}size.exe" CACHE FILEPATH "size tool")

# Prevent CMake from testing the compilers
set(CMAKE_C_COMPILER_WORKS 1)
set(CMAKE_CXX_COMPILER_WORKS 1)
set(CMAKE_ASM_COMPILER_WORKS 1)

# Target Raspberry Pi Zero W (ARM11, ARMv6)
set(CPU_FLAGS "-mcpu=arm1176jzf-s -mfpu=vfp -mfloat-abi=hard")

# Common flags for all languages
set(COMMON_FLAGS "${CPU_FLAGS} -ffunction-sections -fdata-sections -fno-common")
set(COMMON_FLAGS "${COMMON_FLAGS} -Wall -Wextra -Werror")

# Security flags
set(SECURITY_FLAGS "-fstack-protector-strong -D_FORTIFY_SOURCE=2")

# Set language-specific flags
set(CMAKE_C_FLAGS_INIT "${COMMON_FLAGS} ${SECURITY_FLAGS} -std=gnu11")
set(CMAKE_CXX_FLAGS_INIT "${COMMON_FLAGS} ${SECURITY_FLAGS} -std=gnu++17 -fno-exceptions -fno-rtti")
set(CMAKE_ASM_FLAGS_INIT "${COMMON_FLAGS}")

# Debug and Release specific flags
set(CMAKE_C_FLAGS_DEBUG_INIT "-Og -g3 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE_INIT "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG_INIT "-Og -g3 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-O3 -DNDEBUG")

# Linker flags
set(CMAKE_EXE_LINKER_FLAGS_INIT "${CPU_FLAGS} -nostartfiles -Wl,--gc-sections")

# Search paths
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
