#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "security/security.h"
#include "security/security_events.h"
#include "process/process.h"

// Process states
typedef enum {
    PROCESS_STATE_UNUSED,
    PROCESS_STATE_CREATED,
    PROCESS_STATE_READY,
    PROCESS_STATE_RUNNING,
    PROCESS_STATE_BLOCKED,
    PROCESS_STATE_TERMINATED,
    PROCESS_STATE_DEAD,
    PROCESS_STATE_WAITING
} ProcessState;

// Process priority levels
typedef enum {
    PROCESS_PRIORITY_IDLE = 0,
    PROCESS_PRIORITY_LOW = 1,
    PROCESS_PRIORITY_NORMAL = 2,
    PROCESS_PRIORITY_HIGH = 3,
    PROCESS_PRIORITY_REALTIME = 4
} ProcessPriority;

// Process security flags
#define PROC_SEC_PRIVILEGED   0x01
#define PROC_SEC_ISOLATED     0x02
#define PROC_SEC_MONITORED    0x04
#define PROC_SEC_SANDBOXED    0x08
#define PROC_SEC_RESTRICTED   0x10

// Process capability flags
#define PROC_CAP_NET_ADMIN    0x0001
#define PROC_CAP_SYS_ADMIN    0x0002
#define PROC_CAP_KILL         0x0004
#define PROC_CAP_NET_RAW      0x0008
#define PROC_CAP_NET_BIND     0x0010
#define PROC_CAP_SYS_MODULE   0x0020
#define PROC_CAP_SYS_RAWIO    0x0040
#define PROC_CAP_SYS_PTRACE   0x0080

// Process control block
typedef struct {
    uint32_t pid;
    ProcessState state;
    uint32_t security_flags;
    void* stack_ptr;
    void* program_counter;
    uint32_t privileges;
    uint32_t memory_quota;
    uint32_t cpu_quota;
    uint32_t parent_pid;
    void* security_context;
    bool is_secure;
    uint32_t capabilities;     // Process capabilities
    uint32_t effective_caps;   // Currently active capabilities
    uint32_t inheritable_caps; // Capabilities that can be inherited
    ProcessPriority priority;
    char name[256];
    uint32_t security_level;
    uint32_t last_activity;
    void* stack_pointer;
    void* memory_context;
} ProcessControlBlock;

// Maximum number of processes
#define MAX_PROCESSES 256

// Process table
static ProcessControlBlock process_table[MAX_PROCESSES];
static uint32_t next_pid = 1;

// Current running process
static ProcessControlBlock* current_process = NULL;

// Initialize process table
bool init_process_table(void) {
    for (size_t i = 0; i < MAX_PROCESSES; i++) {
        process_table[i].state = PROCESS_STATE_UNUSED;
        process_table[i].pid = 0;
        process_table[i].parent_pid = 0;
        process_table[i].security_context = NULL;
        process_table[i].stack_ptr = NULL;
        process_table[i].program_counter = NULL;
    }

    // Create idle process
    create_idle_process();
    return true;
}

// Process management functions
ProcessControlBlock* get_current_process(void) {
    return current_process;
}

uint32_t create_process(const char* name, ProcessPriority priority, uint32_t security_flags) {
    // Find free slot in process table
    int slot = -1;
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (process_table[i].state == PROCESS_STATE_UNUSED) {
            slot = i;
            break;
        }
    }

    if (slot == -1) {
        return 0; // No free slots
    }

    // Initialize process control block
    ProcessControlBlock* pcb = &process_table[slot];
    pcb->pid = next_pid++;
    strncpy(pcb->name, name, sizeof(pcb->name) - 1);
    pcb->name[sizeof(pcb->name) - 1] = '\0';
    pcb->priority = priority;
    pcb->security_flags = security_flags;
    pcb->state = PROCESS_STATE_CREATED;
    pcb->security_level = SECURITY_LEVEL_LOW;
    pcb->last_activity = get_system_time();
    pcb->stack_pointer = NULL;
    pcb->memory_context = NULL;
    pcb->security_context = NULL;

    return pcb->pid;
}

// Schedule tasks
bool schedule_tasks(void) {
    ProcessControlBlock* current = get_current_process();
    ProcessControlBlock* next = NULL;
    uint32_t highest_priority = PROCESS_PRIORITY_IDLE;

    // Find highest priority ready process
    for (int i = 0; i < MAX_PROCESSES; i++) {
        ProcessControlBlock* pcb = &process_table[i];
        if (pcb->state == PROCESS_STATE_READY) {
            if (check_process_security(pcb)) {
                if (pcb->priority > highest_priority) {
                    highest_priority = pcb->priority;
                    next = pcb;
                }
            }
        }
    }

    if (next != NULL && next != current) {
        secure_context_switch(current, next);
        return true;
    }

    return false;
}

// Perform secure context switch
void secure_context_switch(ProcessControlBlock* current, ProcessControlBlock* next) {
    // Save current context if valid
    if (current != NULL) {
        save_secure_context(current);
    }

    // Verify integrity of next process
    if (!verify_process_integrity(next)) {
        handle_security_violation(SECURITY_EVENT_PROCESS_VIOLATION, next);
        return;
    }

    // Update memory context
    update_secure_memory_context(next);

    // Restore next context
    restore_secure_context(next);
}

// Verify process integrity
bool verify_process_integrity(ProcessControlBlock* pcb) {
    // Verify memory integrity
    if (!verify_process_memory(pcb)) {
        notify_security_monitor(SECURITY_EVENT_MEMORY_VIOLATION);
        return false;
    }

    // Verify context integrity
    if (!verify_process_context(pcb)) {
        notify_security_monitor(SECURITY_EVENT_SYSTEM_VIOLATION);
        return false;
    }

    // Verify capability integrity
    if (!verify_capability_integrity(pcb)) {
        notify_security_monitor(SECURITY_EVENT_PROCESS_VIOLATION);
        return false;
    }

    return true;
}

// Handle security violation
void handle_security_violation(SecurityEventType event_type, const void* event_data) {
    // Log security event
    SecurityEvent event = {
        .type = event_type,
        .timestamp = get_system_time(),
        .process_id = get_current_process()->pid,
        .severity = 3, // Critical
        .data = (void*)event_data,
        .data_size = sizeof(ProcessControlBlock)
    };
    
    log_security_event(&event);

    // Terminate violating process
    ProcessControlBlock* pcb = (ProcessControlBlock*)event_data;
    terminate_process(pcb->pid);

    // Notify security monitor
    notify_security_monitor(event_type);
}

// Terminate process
void terminate_process(uint32_t pid) {
    ProcessControlBlock* pcb = find_process(pid);
    if (pcb == NULL) {
        return;
    }

    // Clean up process resources
    pcb->state = PROCESS_STATE_DEAD;
    pcb->security_level = SECURITY_LEVEL_LOW;
    pcb->priority = PROCESS_PRIORITY_IDLE;
    pcb->security_flags = 0;

    // Free memory
    free_secure_memory(pcb);
}

// Monitor processes
void monitor_processes(void) {
    // Monitor all active processes
    for (int i = 0; i < MAX_PROCESSES; i++) {
        ProcessControlBlock* pcb = &process_table[i];
        if (pcb->state == PROCESS_STATE_RUNNING) {
            // Check process behavior
            check_process_behavior(pcb);

            // Check resource usage
            check_process_resources(pcb);

            // Verify security constraints
            verify_security_constraints(pcb);
        }
    }
}

// Check process behavior
void check_process_behavior(ProcessControlBlock* pcb) {
    // Analyze syscall patterns
    analyze_syscall_pattern(pcb);

    // Check memory access patterns
    check_memory_access_pattern(pcb);

    // Analyze CPU usage
    analyze_cpu_usage(pcb);

    // Detect exploit attempts
    detect_exploit_attempts(pcb);

    // Monitor capability usage
    monitor_capability_usage(pcb);

    // Detect privilege escalation
    detect_privilege_escalation(pcb);
}

// Monitor capability usage
void monitor_capability_usage(ProcessControlBlock* pcb) {
    // Update capability usage statistics
    update_capability_usage_stats(pcb);

    // Detect suspicious capability usage
    if (detect_suspicious_capability_usage(pcb)) {
        notify_security_monitor(SECURITY_EVENT_PROCESS_VIOLATION);
    }

    // Monitor privileged operations
    monitor_privileged_operations(pcb);
}
