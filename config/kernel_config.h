#ifndef KERNEL_CONFIG_H
#define KERNEL_CONFIG_H

// Memory Configuration
#define KERNEL_HEAP_SIZE     (16 * 1024 * 1024)  // 16MB
#define MAX_PROCESSES        1024
#define SECURE_MEMORY_POOL   (10 * 1024 * 1024)  // 10MB
#define MAX_NETWORK_INTERFACES 8

// Security Configuration
#define ENABLE_ASLR          1
#define ENABLE_DEP           1
#define ENABLE_STACK_GUARD   1
#define ENABLE_CFI           1

// Network Security
#define MAX_CONNECTIONS      1024
#define ENCRYPTED_COMMS      1
#define SECURE_PROTOCOLS     1
#define TRAFFIC_MONITORING   1

// Process Security
#define PROCESS_ISOLATION    1
#define SYSCALL_FILTERING    1
#define CAPABILITY_SYSTEM    1
#define BEHAVIOR_MONITORING  1

// Memory Protection
#define GUARD_PAGES          1
#define MEMORY_ENCRYPTION    1
#define SECURE_HEAP          1
#define STACK_PROTECTION     1

// Debug Configuration
#ifdef DEBUG_BUILD
    #define ENABLE_LOGGING   1
    #define LOG_LEVEL        3  // Verbose
#else
    #define ENABLE_LOGGING   0
    #define LOG_LEVEL        0  // None
#endif

// IDE Configuration
#define MAX_PROJECT_SIZE     (1024 * 1024 * 1024)  // 1GB
#define MAX_TEMPLATE_SIZE    (1024 * 1024)         // 1MB
#define MAX_FILE_SIZE        (100 * 1024 * 1024)   // 100MB
#define MAX_BUFFER_SIZE      (10 * 1024 * 1024)    // 10MB

// Malware Development
#define ENABLE_TEMPLATES     1
#define ENABLE_OBFUSCATION   1
#define ENABLE_ANTI_DEBUG    1
#define ENABLE_ENCRYPTION    1

// Analysis Features
#define ENABLE_CODE_ANALYSIS 1
#define ENABLE_VULN_SCAN     1
#define ENABLE_BEHAVIOR_ANALYSIS 1
#define ENABLE_CRYPTO_ANALYSIS 1

// Build Configuration
#define TARGET_ARCH          "arm"
#define TARGET_OS            "ghostos"
#define COMPILER_VERSION     "gcc-9.3.0"
#define TOOLCHAIN_PREFIX     "arm-none-eabi-"

#endif // KERNEL_CONFIG_H
