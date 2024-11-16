#ifndef HW_CRYPTO_H
#define HW_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Hardware Security Module Constants */
#define MAX_KERNEL_SIZE (16 * 1024 * 1024)  // 16MB max kernel size
#define KERNEL_LOAD_ADDRESS 0x8000           // Standard RPi kernel load address

/* Security Alert Types */
#define ALERT_INTEGRITY_VIOLATION 1
#define ALERT_SIGNATURE_INVALID   2
#define ALERT_MEMORY_VIOLATION    3
#define ALERT_BOOT_FAILURE       4

/* Hardware Crypto Functions */
bool hw_crypto_init(void);
bool hw_calculate_hash(const void* data, size_t size, uint8_t* hash);
bool hw_verify_signature(const uint8_t* hash, size_t hash_size,
                        const uint8_t* signature, size_t sig_size,
                        const uint8_t* public_key, size_t key_size);

/* Memory Protection */
bool enable_memory_protection(void);
bool init_secure_regions(void);
bool verify_memory_integrity(void);

/* Security Functions */
void trigger_security_alert(uint32_t alert_type, uint32_t data);
void log_error(const char* message);

#endif /* HW_CRYPTO_H */
