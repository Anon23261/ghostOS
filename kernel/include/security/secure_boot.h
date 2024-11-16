#ifndef GHOST_SECURE_BOOT_H
#define GHOST_SECURE_BOOT_H

#include <stdint.h>
#include <stdbool.h>

// Secure Boot Configuration
#define GHOST_SECURE_BOOT_VERSION 1
#define GHOST_SECURE_BOOT_MAGIC 0x4748535442544C44 // "GHSTBTLD"

// Security Levels
typedef enum {
    SECURITY_LEVEL_MINIMAL = 0,
    SECURITY_LEVEL_STANDARD = 1,
    SECURITY_LEVEL_HIGH = 2,
    SECURITY_LEVEL_MAXIMUM = 3
} SecurityLevel;

// Boot Stage Definitions
typedef enum {
    BOOT_STAGE_INITIAL = 0,
    BOOT_STAGE_HARDWARE_INIT = 1,
    BOOT_STAGE_SECURITY_INIT = 2,
    BOOT_STAGE_KERNEL_LOAD = 3,
    BOOT_STAGE_COMPLETE = 4
} BootStage;

// Boot Status Codes
typedef enum {
    BOOT_STATUS_SUCCESS = 0,
    BOOT_STATUS_SIGNATURE_INVALID = -1,
    BOOT_STATUS_HASH_MISMATCH = -2,
    BOOT_STATUS_SECURITY_VIOLATION = -3,
    BOOT_STATUS_HARDWARE_ERROR = -4,
    BOOT_STATUS_MEMORY_ERROR = -5
} BootStatus;

// Function Declarations
bool verify_secure_boot(void);
bool verify_boot_signature(const void* data, size_t size);
bool verify_kernel_integrity(void);
void secure_boot_panic(const char* message);
BootStatus init_secure_boot(void);
void log_boot_event(const char* message, BootStage stage);

#endif // GHOST_SECURE_BOOT_H
