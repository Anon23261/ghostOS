#include "../../config/kernel_config.h"
#include <stdint.h>
#include <stdbool.h>

// Process states
typedef enum {
    PROCESS_STATE_NEW,
    PROCESS_STATE_READY,
    PROCESS_STATE_RUNNING,
    PROCESS_STATE_BLOCKED,
    PROCESS_STATE_TERMINATED
} ProcessState;

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
    uint32_t security_context;
    bool is_secure;
    uint32_t capabilities;     // Process capabilities
    uint32_t effective_caps;   // Currently active capabilities
    uint32_t inheritable_caps; // Capabilities that can be inherited
} ProcessControlBlock;

// Process table
static ProcessControlBlock process_table[MAX_PROCESSES];
static uint32_t next_pid = 1;

// Initialize process management
void init_process_table(void) {
    // Clear process table
    for (int i = 0; i < MAX_PROCESSES; i++) {
        process_table[i].pid = 0;
        process_table[i].state = PROCESS_STATE_NEW;
        process_table[i].security_flags = 0;
        process_table[i].capabilities = 0;
        process_table[i].effective_caps = 0;
        process_table[i].inheritable_caps = 0;
    }

    // Initialize idle process
    create_idle_process();
}

// Create new process with security context
uint32_t create_process(void* entry_point, uint32_t security_flags) {
    uint32_t pid = next_pid++;
    ProcessControlBlock* pcb = &process_table[pid % MAX_PROCESSES];

    // Initialize PCB
    pcb->pid = pid;
    pcb->state = PROCESS_STATE_NEW;
    pcb->security_flags = security_flags;
    pcb->program_counter = entry_point;
    pcb->is_secure = true;

    // Initialize capabilities
    pcb->capabilities = 0;
    pcb->effective_caps = 0;
    pcb->inheritable_caps = 0;

    // Set default capabilities based on security flags
    if (security_flags & PROC_SEC_PRIVILEGED) {
        pcb->capabilities = PROC_CAP_SYS_ADMIN | PROC_CAP_NET_ADMIN;
        pcb->effective_caps = pcb->capabilities;
    }

    // Allocate secure stack
    pcb->stack_ptr = allocate_secure_stack();

    // Set up process isolation
    if (security_flags & PROC_SEC_ISOLATED) {
        setup_process_isolation(pcb);
    }

    // Initialize security context
    pcb->security_context = create_security_context(security_flags);

    return pid;
}

// Process scheduler with security checks
void schedule_tasks(void) {
    ProcessControlBlock* current = get_current_process();
    ProcessControlBlock* next = NULL;

    // Find next runnable process
    for (int i = 0; i < MAX_PROCESSES; i++) {
        ProcessControlBlock* pcb = &process_table[i];
        if (pcb->state == PROCESS_STATE_READY) {
            // Perform security checks
            if (check_process_security(pcb)) {
                next = pcb;
                break;
            }
        }
    }

    if (next) {
        // Context switch with security measures
        secure_context_switch(current, next);
    }
}

// Security context switch
void secure_context_switch(ProcessControlBlock* current, ProcessControlBlock* next) {
    // Save current context
    if (current) {
        save_secure_context(current);
    }

    // Security checks before switch
    if (!verify_process_integrity(next)) {
        handle_security_violation(next);
        return;
    }

    // Update MMU context
    update_secure_memory_context(next);

    // Restore next context
    restore_secure_context(next);
}

// Process security verification
bool verify_process_integrity(ProcessControlBlock* pcb) {
    // Verify process memory regions
    if (!verify_process_memory(pcb)) {
        log_security_event(SECURITY_EVENT_MEMORY_VIOLATION, pcb->pid, 0);
        return false;
    }

    // Check for capability violations
    if (!verify_capability_integrity(pcb)) {
        log_security_event(SECURITY_EVENT_CAPABILITY_VIOLATION, pcb->pid, 0);
        return false;
    }

    // Verify security context
    if (!verify_security_context_integrity(pcb->security_context)) {
        log_security_event(SECURITY_EVENT_CONTEXT_VIOLATION, pcb->pid, 0);
        return false;
    }

    // Check stack integrity
    if (!verify_stack_integrity(pcb->stack_ptr)) {
        return false;
    }

    // Verify code segment
    if (!verify_code_integrity(pcb->program_counter)) {
        return false;
    }

    return true;
}

// Capability checking
bool check_process_capability(ProcessControlBlock* pcb, uint32_t required_cap) {
    return (pcb->effective_caps & required_cap) == required_cap;
}

// Handle process security violation
void handle_security_violation(ProcessControlBlock* pcb) {
    // Log security event
    log_security_event(SECURITY_EVENT_PROCESS_VIOLATION,
                      pcb->pid,
                      pcb->security_context);

    // Terminate process
    terminate_process(pcb->pid);

    // Notify security monitor
    notify_security_monitor(SECURITY_EVENT_PROCESS_VIOLATION);
}

// Process monitoring
void monitor_processes(void) {
    for (int i = 0; i < MAX_PROCESSES; i++) {
        ProcessControlBlock* pcb = &process_table[i];
        if (pcb->state != PROCESS_STATE_NEW && pcb->state != PROCESS_STATE_TERMINATED) {
            // Check process behavior
            check_process_behavior(pcb);

            // Monitor resource usage
            check_process_resources(pcb);

            // Verify security constraints
            verify_security_constraints(pcb);
        }
    }
}

// Process behavior analysis
void check_process_behavior(ProcessControlBlock* pcb) {
    // Check for suspicious system calls
    analyze_syscall_pattern(pcb);

    // Monitor memory access patterns
    check_memory_access_pattern(pcb);

    // Analyze CPU usage patterns
    analyze_cpu_usage(pcb);

    // Check for potential exploits
    detect_exploit_attempts(pcb);

    // Check for capability abuse
    monitor_capability_usage(pcb);

    // Check for privilege escalation attempts
    detect_privilege_escalation(pcb);
}

// Capability monitoring
void monitor_capability_usage(ProcessControlBlock* pcb) {
    // Track capability usage patterns
    update_capability_usage_stats(pcb);

    // Check for suspicious capability combinations
    if (detect_suspicious_capability_usage(pcb)) {
        log_security_event(SECURITY_EVENT_SUSPICIOUS_CAPS, pcb->pid, pcb->effective_caps);
    }

    // Monitor privileged operations
    monitor_privileged_operations(pcb);
}

// Terminate process securely
void terminate_process(uint32_t pid) {
    ProcessControlBlock* pcb = &process_table[pid % MAX_PROCESSES];

    // Clean up security context
    cleanup_security_context(pcb->security_context);

    // Free secure memory
    free_secure_memory(pcb);

    // Clear process state
    pcb->state = PROCESS_STATE_TERMINATED;
    pcb->security_flags = 0;
    pcb->security_context = 0;

    // Notify parent process
    notify_parent_process(pcb->parent_pid);
}
