#ifndef GHOST_CRYPTO_H
#define GHOST_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include "secure_boot.h"

// Crypto functions
bool init_crypto(void);
bool verify_signature(const uint8_t* data, size_t data_size,
                     const uint8_t* signature, size_t sig_size,
                     const uint8_t* public_key, size_t key_size);
bool generate_hash(const void* data, size_t size, uint8_t* hash);
bool encrypt_data(const void* in_data, size_t in_size,
                 void* out_data, size_t* out_size,
                 const uint8_t* key, size_t key_size);
bool decrypt_data(const void* in_data, size_t in_size,
                 void* out_data, size_t* out_size,
                 const uint8_t* key, size_t key_size);

// Random number generation
bool get_random_bytes(void* buffer, size_t size);
uint32_t get_random_uint32(void);

// Key management
bool generate_key_pair(uint8_t* public_key, uint8_t* private_key, size_t key_size);
bool import_public_key(const uint8_t* key_data, size_t key_size);
bool export_public_key(uint8_t* key_buffer, size_t* key_size);

#endif // GHOST_CRYPTO_H
