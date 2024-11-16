#include <stdint.h>
#include <stdbool.h>
#include "include/secure_boot.h"
#include "include/crypto.h"
#include "include/hw_crypto.h"
#include <string.h>

// Security keys and certificates
static uint8_t root_public_key[RSA_KEY_SIZE];
static uint8_t boot_signature[RSA_SIGNATURE_SIZE];
static uint8_t secure_boot_hash[SHA256_HASH_SIZE];

// Secure Boot States
typedef enum {
    SECURE_BOOT_INIT = 0,
    SECURE_BOOT_KEYS_LOADED,
    SECURE_BOOT_VERIFIED,
    SECURE_BOOT_FAILED,
    SECURE_BOOT_COMPLETE
} SecureBootState;

static SecureBootState boot_state = SECURE_BOOT_INIT;

// Initialize secure boot with error handling
bool secure_boot_init(void) {
    bool success = true;
    
    // Initialize hardware security module
    if (!hw_crypto_init()) {
        log_error("Failed to initialize hardware security module");
        boot_state = SECURE_BOOT_FAILED;
        return false;
    }
    
    // Load and verify root public key
    if (!load_root_key(root_public_key, RSA_KEY_SIZE)) {
        log_error("Failed to load root public key");
        boot_state = SECURE_BOOT_FAILED;
        return false;
    }
    
    // Initialize secure memory regions with protection
    if (!init_secure_regions()) {
        log_error("Failed to initialize secure regions");
        boot_state = SECURE_BOOT_FAILED;
        return false;
    }
    
    // Enable memory protection
    if (!enable_memory_protection()) {
        log_error("Failed to enable memory protection");
        boot_state = SECURE_BOOT_FAILED;
        return false;
    }
    
    boot_state = SECURE_BOOT_KEYS_LOADED;
    return true;
}

// Verify kernel integrity and signature
int verify_kernel_signature(void) {
    const uint8_t* kernel_image = (uint8_t*)KERNEL_LOAD_ADDRESS;
    size_t kernel_size = get_kernel_size();
    
    // Verify kernel size
    if (kernel_size == 0 || kernel_size > MAX_KERNEL_SIZE) {
        log_error("Invalid kernel size");
        boot_state = SECURE_BOOT_FAILED;
        return -1;
    }
    
    // Calculate kernel hash
    uint8_t kernel_hash[SHA256_HASH_SIZE];
    if (!hw_calculate_hash(kernel_image, kernel_size, kernel_hash)) {
        log_error("Failed to calculate kernel hash");
        boot_state = SECURE_BOOT_FAILED;
        return -2;
    }
    
    // Load and verify kernel signature
    if (!load_kernel_signature(boot_signature, RSA_SIGNATURE_SIZE)) {
        log_error("Failed to load kernel signature");
        boot_state = SECURE_BOOT_FAILED;
        return -3;
    }
    
    // Verify signature using hardware security module
    if (!hw_verify_signature(kernel_hash, SHA256_HASH_SIZE, 
                           boot_signature, root_public_key)) {
        log_error("Kernel signature verification failed");
        boot_state = SECURE_BOOT_FAILED;
        return -4;
    }
    
    // Verify memory integrity
    if (!verify_memory_integrity()) {
        log_error("Memory integrity check failed");
        boot_state = SECURE_BOOT_FAILED;
        return -5;
    }
    
    // Store verified boot hash
    memcpy(secure_boot_hash, kernel_hash, SHA256_HASH_SIZE);
    boot_state = SECURE_BOOT_VERIFIED;
    
    return 0;
}

// Get secure boot status
SecureBootState get_secure_boot_state(void) {
    return boot_state;
}

// Verify runtime integrity
bool verify_runtime_integrity(void) {
    uint8_t current_hash[SHA256_HASH_SIZE];
    const uint8_t* kernel_image = (uint8_t*)KERNEL_LOAD_ADDRESS;
    size_t kernel_size = get_kernel_size();
    
    // Calculate current kernel hash
    if (!hw_calculate_hash(kernel_image, kernel_size, current_hash)) {
        log_error("Failed to calculate current kernel hash");
        return false;
    }
    
    // Compare with boot hash
    if (memcmp(current_hash, secure_boot_hash, SHA256_HASH_SIZE) != 0) {
        log_error("Runtime integrity check failed");
        trigger_security_alert(ALERT_INTEGRITY_VIOLATION, 0);
        return false;
    }
    
    return true;
}

// Secure Boot Constants
#define SECURE_BOOT_MAGIC 0x53424F4F /* "SBOO" */
#define MAX_SIGNATURE_SIZE 512
#define MAX_CERT_SIZE 1024

// Secure Boot State
static bool secure_boot_initialized = false;
static uint8_t boot_key[32];
static uint8_t cert_store[MAX_CERT_SIZE];

// Initialize Secure Boot
bool init_secure_boot(void) {
    if (secure_boot_initialized) {
        return true;
    }

    // Load boot key
    if (!load_boot_key(boot_key)) {
        return false;
    }

    // Load certificates
    if (!load_certificates(cert_store)) {
        return false;
    }

    secure_boot_initialized = true;
    return true;
}

// Verify Boot Image
bool verify_boot_image(const void* image, size_t size, const void* signature) {
    if (!secure_boot_initialized) {
        return false;
    }

    // Verify image signature
    if (!verify_signature(image, size, signature, boot_key)) {
        return false;
    }

    // Verify image integrity
    if (!verify_image_integrity(image, size)) {
        return false;
    }

    return true;
}

// Load Next Stage
bool load_next_stage(void* dest, const void* src, size_t size) {
    if (!secure_boot_initialized) {
        return false;
    }

    // Verify stage signature
    if (!verify_stage_signature(src, size)) {
        return false;
    }

    // Decrypt stage if encrypted
    void* decrypted = NULL;
    size_t decrypted_size = 0;
    if (!decrypt_stage(src, size, &decrypted, &decrypted_size)) {
        return false;
    }

    // Copy to destination
    copy_secure_memory(dest, decrypted, decrypted_size);

    // Clean up
    secure_zero_memory(decrypted, decrypted_size);
    return true;
}

// Measure Boot Components
bool measure_boot_components(void) {
    if (!secure_boot_initialized) {
        return false;
    }

    // Measure bootloader
    if (!measure_bootloader()) {
        return false;
    }

    // Measure kernel
    if (!measure_kernel()) {
        return false;
    }

    // Measure initial ramdisk
    if (!measure_initrd()) {
        return false;
    }

    return true;
}

// Extend Boot Measurements
bool extend_measurement(const void* data, size_t size) {
    if (!secure_boot_initialized) {
        return false;
    }

    // Calculate hash
    uint8_t hash[32];
    if (!calculate_hash(data, size, hash)) {
        return false;
    }

    // Extend TPM PCR
    if (!extend_pcr(hash)) {
        return false;
    }

    return true;
}

// Lock Boot Services
void lock_boot_services(void) {
    if (!secure_boot_initialized) {
        return;
    }

    // Lock boot key access
    secure_zero_memory(boot_key, sizeof(boot_key));

    // Lock certificate store
    secure_zero_memory(cert_store, sizeof(cert_store));

    // Lock boot services
    secure_boot_initialized = false;
}
