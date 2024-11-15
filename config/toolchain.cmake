# GhostOS Toolchain Configuration for Raspberry Pi Zero W
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR ARM)

# Toolchain paths
set(TOOLCHAIN_PREFIX "arm-none-eabi-")
set(TOOLCHAIN_BIN_DIR "${CMAKE_CURRENT_LIST_DIR}/../tools/gcc-arm-none-eabi/bin")

# Cross-compilation tools
set(CMAKE_C_COMPILER "${TOOLCHAIN_BIN_DIR}/${TOOLCHAIN_PREFIX}gcc")
set(CMAKE_CXX_COMPILER "${TOOLCHAIN_BIN_DIR}/${TOOLCHAIN_PREFIX}g++")
set(CMAKE_ASM_COMPILER "${TOOLCHAIN_BIN_DIR}/${TOOLCHAIN_PREFIX}gcc")
set(CMAKE_OBJCOPY "${TOOLCHAIN_BIN_DIR}/${TOOLCHAIN_PREFIX}objcopy")
set(CMAKE_SIZE "${TOOLCHAIN_BIN_DIR}/${TOOLCHAIN_PREFIX}size")

# Target-specific flags for Raspberry Pi Zero W (BCM2835)
set(CPU_FLAGS "-mcpu=arm1176jzf-s -mfpu=vfp -mfloat-abi=hard")
set(COMMON_FLAGS "-ffunction-sections -fdata-sections -fno-exceptions ${CPU_FLAGS}")

# Security-focused compiler flags
set(SECURITY_FLAGS 
    "-fstack-protector-strong"
    "-D_FORTIFY_SOURCE=2"
    "-fPIE"
    "-fPIC"
    "-Wformat"
    "-Wformat-security"
    "-Werror=format-security"
    "-Wstack-protector"
    "-fno-common"
)

# Combine all flags
set(CMAKE_C_FLAGS "${COMMON_FLAGS} ${SECURITY_FLAGS} -std=gnu11")
set(CMAKE_CXX_FLAGS "${COMMON_FLAGS} ${SECURITY_FLAGS} -std=gnu++17")
set(CMAKE_ASM_FLAGS "${COMMON_FLAGS}")

# Linker flags
set(CMAKE_EXE_LINKER_FLAGS 
    "-Wl,--gc-sections -nostartfiles -nostdlib \
     -Wl,-z,relro,-z,now \
     -Wl,-z,noexecstack \
     -Wl,-z,separate-code"
)

# Search paths
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Build type specific flags
set(CMAKE_C_FLAGS_DEBUG "-Og -g3 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG ${CMAKE_C_FLAGS_DEBUG})
set(CMAKE_CXX_FLAGS_RELEASE ${CMAKE_C_FLAGS_RELEASE})
