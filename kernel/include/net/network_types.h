#ifndef GHOST_NETWORK_TYPES_H
#define GHOST_NETWORK_TYPES_H

#include <stdint.h>

// Forward declarations
struct NetworkInterface;
struct NetworkConnection;
struct NetworkPacket;

// Network event types
typedef enum {
    NET_EVENT_NONE = 0,
    NET_EVENT_CONNECT,
    NET_EVENT_DISCONNECT,
    NET_EVENT_DATA,
    NET_EVENT_ERROR,
    NET_EVENT_TIMEOUT,
    NET_EVENT_SECURITY_VIOLATION,
    NET_EVENT_INTRUSION_DETECTED,
    NET_EVENT_ANOMALY_DETECTED,
    NET_EVENT_BUFFER_FULL,
    NET_EVENT_BUFFER_EMPTY,
    NET_EVENT_INTERFACE_DOWN,
    NET_EVENT_INTERFACE_UP
} NetworkEventType;

// Network connection states
typedef enum {
    NET_STATE_CLOSED = 0,
    NET_STATE_LISTENING,
    NET_STATE_CONNECTING,
    NET_STATE_CONNECTED,
    NET_STATE_CLOSING,
    NET_STATE_ERROR
} NetworkState;

// Network packet flags
typedef enum {
    NET_FLAG_NONE = 0x0,
    NET_FLAG_ENCRYPTED = 0x1,
    NET_FLAG_COMPRESSED = 0x2,
    NET_FLAG_FRAGMENTED = 0x4,
    NET_FLAG_URGENT = 0x8,
    NET_FLAG_CONTROL = 0x10,
    NET_FLAG_SECURE = 0x20,
    NET_FLAG_VERIFIED = 0x40,
    NET_FLAG_SIGNED = 0x80
} NetworkFlags;

// Network address structure
typedef struct {
    uint32_t address;    // IPv4 address
    uint16_t port;       // Port number
    uint16_t reserved;   // Reserved for alignment
} NetworkAddress;

// Network statistics structure
typedef struct {
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint32_t errors_sent;
    uint32_t errors_received;
    uint32_t packets_dropped;
    uint32_t security_violations;
} NetworkStats;

// Network security event structure
typedef struct {
    NetworkEventType type;
    uint32_t severity;
    uint32_t timestamp;
    NetworkAddress source;
    NetworkAddress destination;
    uint32_t flags;
    uint32_t sequence;
    void* context;
} NetworkSecurityEvent;

#endif // GHOST_NETWORK_TYPES_H
