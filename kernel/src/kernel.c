#include "../include/kernel.h"
#include "../include/mm/memory.h"
#include "../include/process/process.h"
#include "../include/security/security.h"
#include "../include/net/network.h"
#include "../../bootloader/include/bcm2835.h"

/* Global kernel state */
static struct {
    uint32_t boot_time;
    uint32_t uptime;
    uint8_t security_level;
    bool is_initialized;
} kernel_state = {0};

/* Early initialization before memory management is available */
static void early_init(void) {
    /* Disable all interrupts initially */
    disable_interrupts();
    
    /* Initialize hardware-specific features */
    *((volatile uint32_t*)(PERIPHERAL_BASE + 0x200000)) = 0;  // Reset GPIO
    *((volatile uint32_t*)(PERIPHERAL_BASE + 0x3000)) = 0;    // Reset Timer
    
    /* Set up initial security state */
    kernel_state.security_level = SEC_LEVEL_KERNEL;
    kernel_state.is_initialized = false;
}

/* Main kernel initialization */
void kernel_init(void) {
    if (kernel_state.is_initialized) {
        kernel_panic("Kernel already initialized!");
        return;
    }

    /* Perform early initialization */
    early_init();

    /* Initialize memory management first */
    mm_init();

    /* Verify secure boot */
    if (security_verify_boot() != GHOST_SUCCESS) {
        kernel_panic("Secure boot verification failed!");
        return;
    }

    /* Initialize core subsystems */
    security_init();
    process_init();
    scheduler_init();
    network_init();

    /* Start security monitoring */
    security_monitor_init();

    /* Record boot time and mark as initialized */
    kernel_state.boot_time = *((volatile uint32_t*)(TIMER_BASE + 0x04)); // Read system timer
    kernel_state.is_initialized = true;

    /* Enable interrupts now that everything is set up */
    enable_interrupts();

    /* Log successful boot */
    security_event_t boot_event = {
        .type = SEC_EVENT_BOOT,
        .timestamp = kernel_state.boot_time,
        .process_id = 0,
        .security_level = SEC_LEVEL_KERNEL,
        .data = {0}
    };
    security_log_event(&boot_event);
}

/* Kernel panic handler */
void kernel_panic(const char* message) {
    /* Disable interrupts immediately */
    disable_interrupts();

    /* Log the panic */
    security_event_t panic_event = {
        .type = SEC_EVENT_ERROR,
        .timestamp = *((volatile uint32_t*)(TIMER_BASE + 0x04)),
        .process_id = 0,
        .security_level = SEC_LEVEL_KERNEL,
        .data = {0}
    };
    security_log_event(&panic_event);

    /* Halt the system */
    while(1) {
        /* System is halted */
    }
}

/* Enable interrupts */
void enable_interrupts(void) {
    __asm__ volatile("cpsie i");
}

/* Disable interrupts */
void disable_interrupts(void) {
    __asm__ volatile("cpsid i");
}
