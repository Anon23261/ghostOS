#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>
#include <stddef.h>

/* Security Event Types */
#define SEC_EVENT_BOOT        0x01
#define SEC_EVENT_MEMORY     0x02
#define SEC_EVENT_PROCESS    0x03
#define SEC_EVENT_NETWORK    0x04
#define SEC_EVENT_SYSCALL    0x05
#define SEC_EVENT_ERROR      0xFF

/* Security Event Structure */
typedef struct {
    uint32_t type;
    uint32_t timestamp;
    uint32_t process_id;
    uint32_t security_level;
    uint32_t data[4];
} security_event_t;

/* Security Functions */
void security_init(void);
int security_verify_boot(void);
int security_log_event(security_event_t* event);
int security_check_permission(uint32_t pid, uint32_t operation);
int security_verify_memory(void* addr, size_t size, uint32_t flags);

/* Secure Boot */
int secure_boot_verify_kernel(void);
int secure_boot_verify_signature(void* data, size_t size, void* signature);
void secure_boot_lock_memory(void);

/* Runtime Security */
void security_monitor_init(void);
int security_monitor_add_check(void (*check_func)(void));
int security_monitor_process(uint32_t pid);
void security_monitor_tick(void);

#endif /* SECURITY_H */
