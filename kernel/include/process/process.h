#ifndef GHOST_PROCESS_H
#define GHOST_PROCESS_H

#include <stdint.h>
#include <stdbool.h>
#include "../security/security_events.h"

// Enum for process state
typedef enum {
    PROCESS_STATE_RUNNING,
    PROCESS_STATE_WAITING,
    PROCESS_STATE_ZOMBIE,
    PROCESS_STATE_DEAD
} ProcessState;

// Enum for security level
typedef enum {
    SECURITY_LEVEL_LOW,
    SECURITY_LEVEL_MEDIUM,
    SECURITY_LEVEL_HIGH
} SecurityLevel;

// Process Control Block structure
typedef struct {
    uint32_t pid;
    char name[32];
    SecurityLevel security_level;
    ProcessState state;
    uint32_t priority;
    uint32_t security_flags;
    uint64_t last_activity;
    void* stack_pointer;
    void* memory_context;
    void* security_context;
} ProcessControlBlock;

// Process security event notification
void notify_security_monitor(SecurityEventType event_type);

// Process security violation handler
void handle_security_violation(SecurityEventType event_type, const void* event_data);

// Process management functions
void secure_context_switch(ProcessControlBlock* current, ProcessControlBlock* next);
ProcessControlBlock* find_process(uint32_t pid);
void free_secure_memory(ProcessControlBlock* pcb);
void analyze_syscall_pattern(ProcessControlBlock* pcb);
void check_memory_access_pattern(ProcessControlBlock* pcb);
void analyze_cpu_usage(ProcessControlBlock* pcb);
void detect_exploit_attempts(ProcessControlBlock* pcb);
void detect_privilege_escalation(ProcessControlBlock* pcb);
void update_capability_usage_stats(ProcessControlBlock* pcb);
bool detect_suspicious_capability_usage(ProcessControlBlock* pcb);
void monitor_privileged_operations(ProcessControlBlock* pcb);
void check_process_resources(ProcessControlBlock* pcb);
void verify_security_constraints(ProcessControlBlock* pcb);

#endif // GHOST_PROCESS_H
