#include "../../include/security/security.h"
#include "../../include/process/process.h"
#include "../../include/mm/memory.h"
#include "../../config/kernel_config.h"
#include <stdint.h>
#include <stdbool.h>

/* Security Monitor Configuration */
#define MAX_SECURITY_EVENTS 1024
#define MAX_SECURITY_CHECKS 32
#define MONITOR_INTERVAL_MS 100

/* Security Event Queue */
static struct {
    security_event_t events[MAX_SECURITY_EVENTS];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
} event_queue = {0};

/* Security Check Registry */
static struct {
    void (*check_funcs[MAX_SECURITY_CHECKS])(void);
    uint32_t check_count;
} security_checks = {0};

/* Monitor State */
static struct {
    bool initialized;
    uint32_t last_check_time;
    uint32_t violations_count;
    uint32_t threat_level;
} monitor_state = {0};

/* Initialize security monitoring */
void security_monitor_init(void) {
    if (monitor_state.initialized) {
        return;
    }

    /* Clear event queue */
    event_queue.head = 0;
    event_queue.tail = 0;
    event_queue.count = 0;

    /* Clear security checks */
    security_checks.check_count = 0;

    /* Initialize monitor state */
    monitor_state.initialized = true;
    monitor_state.last_check_time = 0;
    monitor_state.violations_count = 0;
    monitor_state.threat_level = 0;

    /* Register default security checks */
    security_monitor_add_check(check_memory_integrity);
    security_monitor_add_check(check_process_integrity);
    security_monitor_add_check(check_network_security);
}

/* Add a security check function */
int security_monitor_add_check(void (*check_func)(void)) {
    if (security_checks.check_count >= MAX_SECURITY_CHECKS) {
        return GHOST_ERROR;
    }

    security_checks.check_funcs[security_checks.check_count++] = check_func;
    return GHOST_SUCCESS;
}

/* Log a security event */
int security_log_event(security_event_t* event) {
    if (event_queue.count >= MAX_SECURITY_EVENTS) {
        /* Queue is full, handle as a security incident */
        handle_security_incident(SEC_EVENT_ERROR);
        return GHOST_ERROR;
    }

    /* Add event to queue */
    event_queue.events[event_queue.tail] = *event;
    event_queue.tail = (event_queue.tail + 1) % MAX_SECURITY_EVENTS;
    event_queue.count++;

    /* Check if this event requires immediate attention */
    if (event->type == SEC_EVENT_ERROR || 
        event->security_level <= SEC_LEVEL_SYSTEM) {
        handle_security_incident(event->type);
    }

    return GHOST_SUCCESS;
}

/* Monitor tick handler */
void security_monitor_tick(void) {
    uint32_t current_time = get_system_time();
    
    /* Check if it's time for security scan */
    if (current_time - monitor_state.last_check_time >= MONITOR_INTERVAL_MS) {
        /* Run all registered security checks */
        for (uint32_t i = 0; i < security_checks.check_count; i++) {
            security_checks.check_funcs[i]();
        }

        /* Process pending security events */
        process_security_events();

        /* Update monitor state */
        monitor_state.last_check_time = current_time;
    }
}

/* Process security events */
static void process_security_events(void) {
    while (event_queue.count > 0) {
        /* Get next event */
        security_event_t* event = &event_queue.events[event_queue.head];
        event_queue.head = (event_queue.head + 1) % MAX_SECURITY_EVENTS;
        event_queue.count--;

        /* Analyze event */
        analyze_security_event(event);

        /* Update threat level */
        update_threat_level(event);
    }
}

/* Handle security incident */
static void handle_security_incident(uint32_t event_type) {
    /* Increment violations count */
    monitor_state.violations_count++;

    /* Take action based on event type */
    switch (event_type) {
        case SEC_EVENT_BOOT:
            /* Verify secure boot chain */
            if (verify_secure_boot() != GHOST_SUCCESS) {
                kernel_panic("Secure boot verification failed");
            }
            break;

        case SEC_EVENT_MEMORY:
            /* Handle memory violation */
            handle_memory_violation(0, 0); /* Address and status from event */
            break;

        case SEC_EVENT_PROCESS:
            /* Handle process violation */
            handle_process_violation();
            break;

        case SEC_EVENT_NETWORK:
            /* Handle network security violation */
            handle_network_violation();
            break;

        case SEC_EVENT_ERROR:
            /* Critical system error */
            if (monitor_state.violations_count > MAX_VIOLATIONS_THRESHOLD) {
                kernel_panic("Security violation threshold exceeded");
            }
            break;
    }
}

/* Update system threat level */
static void update_threat_level(security_event_t* event) {
    /* Calculate new threat level based on event severity */
    uint32_t severity = calculate_event_severity(event);
    
    /* Update threat level using exponential weighted average */
    monitor_state.threat_level = (monitor_state.threat_level * 7 + severity * 3) / 10;

    /* Take action if threat level is too high */
    if (monitor_state.threat_level > HIGH_THREAT_THRESHOLD) {
        enable_enhanced_security();
    }
}
