#ifndef GHOST_SECURITY_EVENTS_H
#define GHOST_SECURITY_EVENTS_H

#include <stdint.h>
#include <stddef.h>

// Security event types
typedef enum {
    // Process events (0-9)
    SECURITY_EVENT_PROCESS_VIOLATION = 0,
    SECURITY_EVENT_PROCESS_CRASH = 1,
    
    // Memory events (10-19)
    SECURITY_EVENT_MEMORY_VIOLATION = 10,
    SECURITY_EVENT_STACK_OVERFLOW = 11,
    
    // Network events (20-29)
    SECURITY_EVENT_NETWORK_INTRUSION = 20,
    SECURITY_EVENT_NETWORK_ANOMALY = 21,
    SECURITY_EVENT_SUSPICIOUS_TRAFFIC = 22,
    
    // System events (30-39)
    SECURITY_EVENT_SYSTEM_VIOLATION = 30,
    SECURITY_EVENT_UNAUTHORIZED_ACCESS = 31,
    
    // Crypto events (40-49)
    SECURITY_EVENT_CRYPTO_FAILURE = 40,
    SECURITY_EVENT_KEY_COMPROMISE = 41
} SecurityEventType;

// Security event data structure
typedef struct {
    SecurityEventType type;
    uint32_t timestamp;
    uint32_t process_id;
    uint32_t severity;
    void* data;
    size_t data_size;
} SecurityEvent;

// Security event functions
void init_security_events(void);
void register_security_event(SecurityEventType type, const void* data, size_t size);
void handle_security_event(SecurityEvent* event);
void log_security_event(const SecurityEvent* event);

#endif // GHOST_SECURITY_EVENTS_H
