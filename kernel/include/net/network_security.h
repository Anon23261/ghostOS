#ifndef GHOST_NETWORK_SECURITY_H
#define GHOST_NETWORK_SECURITY_H

#include <stdint.h>
#include <stdbool.h>
#include "../security/security_events.h"
#include "network.h"
#include "network_errors.h"

// Security levels
typedef enum {
    NET_SECURITY_NONE = 0,
    NET_SECURITY_BASIC = 1,
    NET_SECURITY_ENHANCED = 2,
    NET_SECURITY_MAX = 3
} NetworkSecurityLevel;

// Security violation types
typedef enum {
    NET_VIOLATION_NONE = 0,
    NET_VIOLATION_UNAUTHORIZED = 1,
    NET_VIOLATION_TAMPERING = 2,
    NET_VIOLATION_OVERFLOW = 3,
    NET_VIOLATION_REPLAY = 4,
    NET_VIOLATION_PROTOCOL = 5,
    NET_VIOLATION_INTRUSION = 6,
    NET_VIOLATION_ANOMALY = 7
} NetworkViolationType;

// Security statistics
typedef struct {
    uint32_t violations_detected;
    uint32_t packets_encrypted;
    uint32_t packets_decrypted;
    uint32_t failed_authentications;
    uint64_t last_violation_timestamp;
    NetworkViolationType last_violation_type;
    uint32_t intrusion_attempts;
    uint32_t anomalies_detected;
} NetworkSecurityStats;

// Security event structure
typedef struct {
    NetworkEventType type;
    NetworkViolationType violation;
    uint64_t timestamp;
    uint32_t process_id;
    NetworkAddress source;
    NetworkAddress destination;
    uint32_t flags;
    uint8_t data[256];
} NetworkSecurityEvent;

// Initialization and cleanup
NetworkError init_network_security(void);
NetworkError cleanup_network_security(void);

// Connection security
NetworkError setup_connection_encryption(NetworkConnection* conn, NetworkSecurityLevel level);
NetworkError apply_security_policies(NetworkConnection* conn);
NetworkError verify_connection_integrity(NetworkConnection* conn);
NetworkError handle_connection_timeout(NetworkConnection* conn);

// Traffic analysis
NetworkError analyze_traffic_pattern(NetworkConnection* conn, NetworkSecurityStats* stats);
NetworkError detect_state_violation(NetworkConnection* conn, NetworkViolationType* violation);
NetworkError handle_security_violation(NetworkConnection* conn, NetworkViolationType violation);
NetworkError check_connection_security_status(NetworkConnection* conn);

// Packet security
NetworkError encrypt_packet_data(NetworkPacket* packet, const void* key, size_t key_size);
NetworkError decrypt_packet_data(NetworkPacket* packet, const void* key, size_t key_size);
NetworkError verify_packet_signature(const NetworkPacket* packet, const void* signature);
NetworkError generate_packet_signature(NetworkPacket* packet, void* signature, size_t sig_size);

// Interface security
NetworkError monitor_interface_security(NetworkInterface* iface);
NetworkError get_interface_security_stats(NetworkInterface* iface, NetworkSecurityStats* stats);
NetworkError set_interface_security_level(NetworkInterface* iface, NetworkSecurityLevel level);

// Audit and logging
NetworkError log_security_event(NetworkConnection* conn, NetworkViolationType violation);
NetworkError get_security_audit_log(void* buffer, size_t size, uint32_t* entries_written);

// Intrusion detection
NetworkError detect_intrusion_attempt(const NetworkPacket* packet);
NetworkError handle_intrusion_attempt(const NetworkSecurityEvent* event);
NetworkError update_intrusion_patterns(const void* patterns, size_t size);

// Anomaly detection
NetworkError detect_network_anomaly(const NetworkConnection* conn);
NetworkError handle_network_anomaly(const NetworkSecurityEvent* event);
NetworkError update_anomaly_thresholds(const void* thresholds, size_t size);

#endif // GHOST_NETWORK_SECURITY_H
