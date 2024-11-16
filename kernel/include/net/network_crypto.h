#ifndef GHOSTOS_NETWORK_CRYPTO_H
#define GHOSTOS_NETWORK_CRYPTO_H

#include <stdint.h>
#include "network_types.h"
#include "network_errors.h"

// Forward declarations
typedef struct CryptoContext CryptoContext;
typedef struct SecurityCertificate SecurityCertificate;

// Crypto subsystem initialization/cleanup
NetworkError init_network_crypto(void);
NetworkError cleanup_network_crypto(void);

// Crypto context management
NetworkError create_crypto_context(CryptoContext** context);
NetworkError destroy_crypto_context(CryptoContext* context);

// Packet encryption/decryption
NetworkError encrypt_packet(NetworkPacket* packet, CryptoContext* context);
NetworkError decrypt_packet(NetworkPacket* packet, CryptoContext* context);

// Certificate operations
NetworkError generate_certificate(SecurityCertificate** cert);
NetworkError verify_certificate(const SecurityCertificate* cert);
NetworkError destroy_certificate(SecurityCertificate* cert);

#endif // GHOSTOS_NETWORK_CRYPTO_H
