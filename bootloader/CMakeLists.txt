# Bootloader CMake Configuration
add_library(ghost_bootloader STATIC
    boot.S
    secure_boot.c
)

target_include_directories(ghost_bootloader
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Base compiler flags for ARM
set(ARM_FLAGS
    -mcpu=arm1176jzf-s
    -mfpu=vfp
    -mfloat-abi=hard
    -ffreestanding
    -nostdlib
)

# Optimization and debug flags
set(OPT_FLAGS
    -ffunction-sections
    -fdata-sections
    -fno-common
    -fno-exceptions
)

# Warning flags
set(WARN_FLAGS
    -Wall
    -Wextra
    -Werror
    -Wstack-usage=2048
)

# Security flags (only those supported by arm-none-eabi-gcc)
set(SECURITY_FLAGS
    -fno-builtin
    -fno-strict-aliasing
)

# Combine all flags
target_compile_options(ghost_bootloader
    PRIVATE
    ${ARM_FLAGS}
    ${OPT_FLAGS}
    ${WARN_FLAGS}
    ${SECURITY_FLAGS}
)

# Linker flags
target_link_options(ghost_bootloader
    PRIVATE
    ${ARM_FLAGS}
    -Wl,--gc-sections
    -nostartfiles
    -nodefaultlibs
    -nostdlib
    -static
)
