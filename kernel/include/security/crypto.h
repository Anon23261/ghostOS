#ifndef GHOST_CRYPTO_H
#define GHOST_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

// Cryptographic Algorithm Identifiers
typedef enum {
    CRYPTO_ALG_AES_256_GCM = 0,
    CRYPTO_ALG_CHACHA20_POLY1305 = 1,
    CRYPTO_ALG_SHA3_512 = 2,
    CRYPTO_ALG_ED25519 = 3
} CryptoAlgorithm;

// Cryptographic Key Types
typedef enum {
    KEY_TYPE_SYMMETRIC = 0,
    KEY_TYPE_ASYMMETRIC_PUBLIC = 1,
    KEY_TYPE_ASYMMETRIC_PRIVATE = 2
} KeyType;

// Cryptographic Context
typedef struct {
    CryptoAlgorithm algorithm;
    KeyType key_type;
    uint8_t* key_data;
    size_t key_size;
    void* algorithm_context;
} CryptoContext;

// Function Declarations
bool init_crypto_subsystem(void);
CryptoContext* create_crypto_context(CryptoAlgorithm alg, KeyType type);
void destroy_crypto_context(CryptoContext* ctx);

// Encryption/Decryption
bool encrypt_data(CryptoContext* ctx, const void* input, size_t input_size,
                 void* output, size_t* output_size);
bool decrypt_data(CryptoContext* ctx, const void* input, size_t input_size,
                 void* output, size_t* output_size);

// Hashing
bool calculate_hash(CryptoAlgorithm alg, const void* data, size_t size,
                   uint8_t* hash, size_t* hash_size);

// Digital Signatures
bool sign_data(CryptoContext* ctx, const void* data, size_t size,
               uint8_t* signature, size_t* signature_size);
bool verify_signature(CryptoContext* ctx, const void* data, size_t size,
                     const uint8_t* signature, size_t signature_size);

// Key Management
bool generate_key_pair(CryptoAlgorithm alg, uint8_t* public_key, size_t* public_key_size,
                      uint8_t* private_key, size_t* private_key_size);
bool import_key(CryptoContext* ctx, const uint8_t* key_data, size_t key_size);
bool export_key(CryptoContext* ctx, uint8_t* key_data, size_t* key_size);

// Secure Random Number Generation
bool generate_random(void* buffer, size_t size);

#endif // GHOST_CRYPTO_H
