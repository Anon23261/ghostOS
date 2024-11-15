#include <stdint.h>
#include "bcm2835.h"
#include "security.h"

// GhostOS Kernel Entry Point
void kernel_main(uint32_t r0, uint32_t r1, uint32_t atags)
{
    // Initialize hardware
    bcm2835_init();
    
    // Initialize security subsystems
    security_init();
    memory_protection_init();
    secure_boot_verify();
    
    // Initialize core systems
    scheduler_init();
    virtual_memory_init();
    process_manager_init();
    
    // Start system services
    start_system_services();
}
