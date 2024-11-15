# GhostOS Build Configuration
cmake_minimum_required(VERSION 3.20)
project(GhostOS C ASM)

# Target settings for Raspberry Pi Zero W
set(CMAKE_SYSTEM_NAME "Generic")
set(CMAKE_SYSTEM_PROCESSOR "ARM")

# Toolchain settings
set(TOOLCHAIN_PREFIX "arm-none-eabi-")
set(CMAKE_C_COMPILER "${TOOLCHAIN_PREFIX}gcc")
set(CMAKE_ASM_COMPILER "${TOOLCHAIN_PREFIX}gcc")
set(CMAKE_OBJCOPY "${TOOLCHAIN_PREFIX}objcopy")

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mcpu=arm1176jzf-s -mfpu=vfp -mfloat-abi=hard")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffreestanding -O2 -Wall -Wextra -g")
set(CMAKE_ASM_FLAGS "${CMAKE_C_FLAGS}")

# Security flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE -fPIC -Wformat -Wformat-security")

# Linker settings
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -T${CMAKE_SOURCE_DIR}/kernel/linker.ld")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -nostdlib -Wl,-z,relro,-z,now")

# Build directories
set(KERNEL_SOURCE_DIR "${CMAKE_SOURCE_DIR}/kernel")
set(BOOTLOADER_SOURCE_DIR "${CMAKE_SOURCE_DIR}/bootloader")
set(SECURITY_SOURCE_DIR "${CMAKE_SOURCE_DIR}/kernel/security")

# Include directories
include_directories(
    ${KERNEL_SOURCE_DIR}/include
    ${SECURITY_SOURCE_DIR}/include
    ${BOOTLOADER_SOURCE_DIR}/include
)
