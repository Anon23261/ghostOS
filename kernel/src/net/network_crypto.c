#include <stddef.h>
#include <stdint.h>
#include "../../include/net/network.h"
#include "../../include/net/network_types.h"
#include "../../include/memory/kmalloc.h"
#include "../../include/kernel/spinlock.h"

// Crypto constants
#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE 32
#define HMAC_SIZE 32
#define MAX_NONCE_SIZE 16
#define MAX_IV_SIZE 16
#define MAX_SALT_SIZE 32
#define PBKDF2_ITERATIONS 10000

// Encryption context
typedef struct {
    uint8_t key[AES_KEY_SIZE];
    uint8_t iv[MAX_IV_SIZE];
    uint8_t nonce[MAX_NONCE_SIZE];
    uint32_t counter;
    uint32_t flags;
} CryptoContext;

// Security certificate
typedef struct {
    uint8_t* public_key;
    uint32_t public_key_size;
    uint8_t* signature;
    uint32_t signature_size;
    uint64_t valid_from;
    uint64_t valid_until;
    uint32_t flags;
} SecurityCertificate;

// Static state
static spinlock_t crypto_lock = SPINLOCK_INIT;
static CryptoContext* active_contexts = NULL;
static uint32_t num_contexts = 0;
static uint32_t max_contexts = 256;

// Initialize crypto subsystem
NetworkError init_network_crypto(void) {
    spinlock_acquire(&crypto_lock);

    if (active_contexts) {
        spinlock_release(&crypto_lock);
        return NET_ERR_ALREADY_INITIALIZED;
    }

    active_contexts = kmalloc(sizeof(CryptoContext) * max_contexts);
    if (!active_contexts) {
        spinlock_release(&crypto_lock);
        return NET_ERR_OUT_OF_MEMORY;
    }

    num_contexts = 0;

    spinlock_release(&crypto_lock);
    return NET_ERR_SUCCESS;
}

// Clean up crypto subsystem
NetworkError cleanup_network_crypto(void) {
    spinlock_acquire(&crypto_lock);

    if (active_contexts) {
        kfree(active_contexts);
        active_contexts = NULL;
    }
    num_contexts = 0;

    spinlock_release(&crypto_lock);
    return NET_ERR_SUCCESS;
}

// Create encryption context
NetworkError create_crypto_context(CryptoContext** context) {
    if (!context) return NET_ERR_INVALID_PARAM;

    spinlock_acquire(&crypto_lock);

    if (num_contexts >= max_contexts) {
        spinlock_release(&crypto_lock);
        return NET_ERR_NO_RESOURCES;
    }

    *context = &active_contexts[num_contexts++];

    // Generate random key
    // TODO: Implement proper random number generation
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        (*context)->key[i] = (uint8_t)i;
    }

    // Generate random IV
    for (int i = 0; i < MAX_IV_SIZE; i++) {
        (*context)->iv[i] = (uint8_t)(i * 2);
    }

    // Generate random nonce
    for (int i = 0; i < MAX_NONCE_SIZE; i++) {
        (*context)->nonce[i] = (uint8_t)(i * 3);
    }

    (*context)->counter = 0;
    (*context)->flags = 0;

    spinlock_release(&crypto_lock);
    return NET_ERR_SUCCESS;
}

// Destroy encryption context
NetworkError destroy_crypto_context(CryptoContext* context) {
    if (!context) return NET_ERR_INVALID_PARAM;

    spinlock_acquire(&crypto_lock);

    // Find and remove context
    for (uint32_t i = 0; i < num_contexts; i++) {
        if (&active_contexts[i] == context) {
            // Move last context to this slot if not last
            if (i < num_contexts - 1) {
                active_contexts[i] = active_contexts[num_contexts - 1];
            }
            num_contexts--;
            break;
        }
    }

    spinlock_release(&crypto_lock);
    return NET_ERR_SUCCESS;
}

// AES encryption implementation using AES-256 in CBC mode
static NetworkError aes_encrypt(const uint8_t* key, const uint8_t* iv,
                              const uint8_t* input, uint32_t input_size,
                              uint8_t* output, uint32_t* output_size) {
    if (!key || !iv || !input || !output || !output_size) return NET_ERR_INVALID_PARAM;
    if (*output_size < input_size) return NET_ERR_BUFFER_FULL;

    uint32_t num_blocks = (input_size + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    uint32_t padded_size = num_blocks * AES_BLOCK_SIZE;
    
    // Temporary buffer for padded input
    uint8_t* padded_input = kmalloc(padded_size);
    if (!padded_input) return NET_ERR_OUT_OF_MEMORY;

    // Copy input and add PKCS7 padding
    memcpy(padded_input, input, input_size);
    uint8_t padding = padded_size - input_size;
    memset(padded_input + input_size, padding, padding);

    // Initialize AES key schedule
    uint32_t round_keys[60];
    aes_key_setup(key, round_keys, 256);

    // Previous block for CBC mode
    uint8_t prev_block[AES_BLOCK_SIZE];
    memcpy(prev_block, iv, AES_BLOCK_SIZE);

    // Encrypt each block
    for (uint32_t i = 0; i < num_blocks; i++) {
        uint8_t* curr_block = padded_input + (i * AES_BLOCK_SIZE);
        uint8_t* curr_output = output + (i * AES_BLOCK_SIZE);

        // XOR with previous block (CBC mode)
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            curr_block[j] ^= prev_block[j];
        }

        // Encrypt block
        aes_encrypt_block(curr_block, curr_output, round_keys, 256);

        // Save encrypted block for next iteration
        memcpy(prev_block, curr_output, AES_BLOCK_SIZE);
    }

    kfree(padded_input);
    *output_size = padded_size;
    return NET_ERR_SUCCESS;
}

// AES decryption implementation
static NetworkError aes_decrypt(const uint8_t* key, const uint8_t* iv,
                              const uint8_t* input, uint32_t input_size,
                              uint8_t* output, uint32_t* output_size) {
    if (!key || !iv || !input || !output || !output_size) return NET_ERR_INVALID_PARAM;
    if (input_size % AES_BLOCK_SIZE != 0) return NET_ERR_INVALID_SIZE;
    if (*output_size < input_size) return NET_ERR_BUFFER_FULL;

    uint32_t num_blocks = input_size / AES_BLOCK_SIZE;

    // Initialize AES key schedule
    uint32_t round_keys[60];
    aes_key_setup(key, round_keys, 256);

    // Previous block for CBC mode
    uint8_t prev_block[AES_BLOCK_SIZE];
    memcpy(prev_block, iv, AES_BLOCK_SIZE);

    // Decrypt each block
    for (uint32_t i = 0; i < num_blocks; i++) {
        const uint8_t* curr_input = input + (i * AES_BLOCK_SIZE);
        uint8_t* curr_output = output + (i * AES_BLOCK_SIZE);
        uint8_t temp_block[AES_BLOCK_SIZE];

        // Save current input for next iteration
        memcpy(temp_block, curr_input, AES_BLOCK_SIZE);

        // Decrypt block
        aes_decrypt_block(curr_input, curr_output, round_keys, 256);

        // XOR with previous block (CBC mode)
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            curr_output[j] ^= prev_block[j];
        }

        // Update previous block
        memcpy(prev_block, temp_block, AES_BLOCK_SIZE);
    }

    // Remove PKCS7 padding
    uint8_t padding = output[input_size - 1];
    if (padding > AES_BLOCK_SIZE) return NET_ERR_INVALID_DATA;
    *output_size = input_size - padding;

    return NET_ERR_SUCCESS;
}

// HMAC implementation using SHA-256
static NetworkError calculate_hmac(const uint8_t* key, uint32_t key_size,
                                 const uint8_t* data, uint32_t data_size,
                                 uint8_t* hmac) {
    if (!key || !data || !hmac) return NET_ERR_INVALID_PARAM;

    const uint32_t BLOCK_SIZE = 64; // SHA-256 block size
    uint8_t k_pad[BLOCK_SIZE];
    uint8_t o_key_pad[BLOCK_SIZE];
    uint8_t i_key_pad[BLOCK_SIZE];
    uint8_t temp_hash[32];  // SHA-256 hash size

    // If key is longer than block size, hash it
    if (key_size > BLOCK_SIZE) {
        sha256_init();
        sha256_update(key, key_size);
        sha256_final(k_pad);
        key_size = 32;  // SHA-256 hash size
    } else {
        memcpy(k_pad, key, key_size);
    }

    // Pad key if necessary
    if (key_size < BLOCK_SIZE) {
        memset(k_pad + key_size, 0, BLOCK_SIZE - key_size);
    }

    // Prepare inner and outer key pads
    for (uint32_t i = 0; i < BLOCK_SIZE; i++) {
        o_key_pad[i] = k_pad[i] ^ 0x5c;
        i_key_pad[i] = k_pad[i] ^ 0x36;
    }

    // Inner hash
    sha256_init();
    sha256_update(i_key_pad, BLOCK_SIZE);
    sha256_update(data, data_size);
    sha256_final(temp_hash);

    // Outer hash
    sha256_init();
    sha256_update(o_key_pad, BLOCK_SIZE);
    sha256_update(temp_hash, 32);
    sha256_final(hmac);

    return NET_ERR_SUCCESS;
}

// Encrypt packet
NetworkError encrypt_packet(NetworkPacket* packet, CryptoContext* context) {
    if (!packet || !context) return NET_ERR_INVALID_PARAM;
    if (!packet->data || packet->length == 0) return NET_ERR_PACKET_INVALID;

    spinlock_acquire(&crypto_lock);

    // Allocate buffer for encrypted data
    uint8_t* encrypted = kmalloc(packet->length + HMAC_SIZE);
    if (!encrypted) {
        spinlock_release(&crypto_lock);
        return NET_ERR_OUT_OF_MEMORY;
    }

    // Encrypt data
    uint32_t encrypted_size = packet->length;
    NetworkError err = aes_encrypt(context->key, context->iv,
                                 packet->data, packet->length,
                                 encrypted, &encrypted_size);
    if (err != NET_ERR_SUCCESS) {
        kfree(encrypted);
        spinlock_release(&crypto_lock);
        return err;
    }

    // Calculate HMAC
    err = calculate_hmac(context->key, AES_KEY_SIZE,
                        encrypted, encrypted_size,
                        encrypted + encrypted_size);
    if (err != NET_ERR_SUCCESS) {
        kfree(encrypted);
        spinlock_release(&crypto_lock);
        return err;
    }

    // Replace packet data
    kfree(packet->data);
    packet->data = encrypted;
    packet->length = encrypted_size + HMAC_SIZE;
    packet->flags |= NET_FLAG_ENCRYPTED;

    context->counter++;

    spinlock_release(&crypto_lock);
    return NET_ERR_SUCCESS;
}

// Decrypt packet
NetworkError decrypt_packet(NetworkPacket* packet, CryptoContext* context) {
    if (!packet || !context) return NET_ERR_INVALID_PARAM;
    if (!packet->data || packet->length <= HMAC_SIZE) return NET_ERR_PACKET_INVALID;
    if (!(packet->flags & NET_FLAG_ENCRYPTED)) return NET_ERR_PACKET_INVALID;

    spinlock_acquire(&crypto_lock);

    uint32_t data_size = packet->length - HMAC_SIZE;

    // Verify HMAC
    uint8_t calculated_hmac[HMAC_SIZE];
    NetworkError err = calculate_hmac(context->key, AES_KEY_SIZE,
                                    packet->data, data_size,
                                    calculated_hmac);
    if (err != NET_ERR_SUCCESS) {
        spinlock_release(&crypto_lock);
        return err;
    }

    for (int i = 0; i < HMAC_SIZE; i++) {
        if (calculated_hmac[i] != packet->data[data_size + i]) {
            spinlock_release(&crypto_lock);
            return NET_ERR_INTEGRITY_CHECK_FAILED;
        }
    }

    // Allocate buffer for decrypted data
    uint8_t* decrypted = kmalloc(data_size);
    if (!decrypted) {
        spinlock_release(&crypto_lock);
        return NET_ERR_OUT_OF_MEMORY;
    }

    // Decrypt data
    uint32_t decrypted_size = data_size;
    err = aes_decrypt(context->key, context->iv,
                     packet->data, data_size,
                     decrypted, &decrypted_size);
    if (err != NET_ERR_SUCCESS) {
        kfree(decrypted);
        spinlock_release(&crypto_lock);
        return err;
    }

    // Replace packet data
    kfree(packet->data);
    packet->data = decrypted;
    packet->length = decrypted_size;
    packet->flags &= ~NET_FLAG_ENCRYPTED;

    spinlock_release(&crypto_lock);
    return NET_ERR_SUCCESS;
}

// Generate security certificate
NetworkError generate_certificate(SecurityCertificate** cert) {
    if (!cert) return NET_ERR_INVALID_PARAM;

    // Allocate certificate
    *cert = kmalloc(sizeof(SecurityCertificate));
    if (!*cert) return NET_ERR_OUT_OF_MEMORY;

    // TODO: Implement actual certificate generation
    // This is a placeholder that creates a dummy certificate
    (*cert)->public_key_size = 256;
    (*cert)->public_key = kmalloc((*cert)->public_key_size);
    if (!(*cert)->public_key) {
        kfree(*cert);
        return NET_ERR_OUT_OF_MEMORY;
    }

    (*cert)->signature_size = 64;
    (*cert)->signature = kmalloc((*cert)->signature_size);
    if (!(*cert)->signature) {
        kfree((*cert)->public_key);
        kfree(*cert);
        return NET_ERR_OUT_OF_MEMORY;
    }

    // Fill with dummy data
    for (uint32_t i = 0; i < (*cert)->public_key_size; i++) {
        (*cert)->public_key[i] = (uint8_t)i;
    }
    for (uint32_t i = 0; i < (*cert)->signature_size; i++) {
        (*cert)->signature[i] = (uint8_t)(i * 2);
    }

    (*cert)->valid_from = 0;  // Current time
    (*cert)->valid_until = 0xFFFFFFFF;  // Far future
    (*cert)->flags = 0;

    return NET_ERR_SUCCESS;
}

// Verify security certificate
NetworkError verify_certificate(const SecurityCertificate* cert) {
    if (!cert) return NET_ERR_INVALID_PARAM;
    if (!cert->public_key || !cert->signature) return NET_ERR_CERTIFICATE_INVALID;

    // TODO: Implement actual certificate verification
    // This is a placeholder that always returns success
    return NET_ERR_SUCCESS;
}

// Destroy security certificate
NetworkError destroy_certificate(SecurityCertificate* cert) {
    if (!cert) return NET_ERR_INVALID_PARAM;

    if (cert->public_key) kfree(cert->public_key);
    if (cert->signature) kfree(cert->signature);
    kfree(cert);

    return NET_ERR_SUCCESS;
}
