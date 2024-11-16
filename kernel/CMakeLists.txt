# Kernel CMake Configuration
add_library(ghost_kernel STATIC
    src/kernel_main.c
    src/mm/memory.c
    src/process/process.c
    src/net/network.c
    src/security/secure_boot.c
)

target_include_directories(ghost_kernel
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
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
    -Wstack-usage=4096
)

# Security flags (only those supported by arm-none-eabi-gcc)
set(SECURITY_FLAGS
    -fno-builtin
    -fno-strict-aliasing
)

# Combine all flags
target_compile_options(ghost_kernel
    PRIVATE
    ${ARM_FLAGS}
    ${OPT_FLAGS}
    ${WARN_FLAGS}
    ${SECURITY_FLAGS}
)

# Linker flags
target_link_options(ghost_kernel
    PRIVATE
    ${ARM_FLAGS}
    -Wl,--gc-sections
    -nostartfiles
    -nodefaultlibs
    -nostdlib
    -static
)
