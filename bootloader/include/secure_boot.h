#ifndef GHOST_SECURE_BOOT_H
#define GHOST_SECURE_BOOT_H

#include <stdint.h>
#include <stdbool.h>
#include "hw_crypto.h"

// Secure boot constants
#define RSA_KEY_SIZE 2048
#define SHA256_HASH_SIZE 32
#define MAX_SIGNATURE_SIZE 512
#define MAX_KEY_SIZE 512

// Secure boot functions
bool secure_boot_init(void);
bool verify_kernel_signature(void);
bool load_boot_key(const uint8_t* key_buffer, size_t size);
bool verify_boot_chain(void);
bool verify_code_integrity(const void* code, size_t size);
bool verify_stack_integrity(void);
bool verify_boot_signature(void);
bool verify_stage_signature(const void* stage, size_t size);
bool load_certificates(void* cert_store);
bool verify_image_integrity(const void* image, size_t size);
bool monitor_capability_usage(void* context);

// Secure boot status
typedef enum {
    BOOT_STATUS_OK = 0,
    BOOT_STATUS_SIGNATURE_FAIL,
    BOOT_STATUS_KEY_FAIL,
    BOOT_STATUS_INTEGRITY_FAIL,
    BOOT_STATUS_CHAIN_FAIL
} SecureBootStatus;

// Get last boot status
SecureBootStatus get_boot_status(void);

// Boot measurement functions
bool measure_boot_components(void);
bool extend_measurement(const void* data, size_t size);
bool calculate_hash(const void* data, size_t size, uint8_t* hash);
bool extend_pcr(const uint8_t* hash);

#endif // GHOST_SECURE_BOOT_H
