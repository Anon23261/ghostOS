#include "../../config/kernel_config.h"
#include <stdint.h>
#include <stdbool.h>

// Memory management structures
typedef struct {
    uint32_t virt_addr;
    uint32_t phys_addr;
    uint32_t size;
    uint32_t flags;
} MemoryRegion;

typedef struct {
    uint32_t* page_table;
    uint32_t* page_dir;
    MemoryRegion* regions;
    uint32_t region_count;
} MMUContext;

// Memory protection flags
#define MEM_FLAG_READ     0x01
#define MEM_FLAG_WRITE    0x02
#define MEM_FLAG_EXEC     0x04
#define MEM_FLAG_USER     0x08
#define MEM_FLAG_KERNEL   0x10
#define MEM_FLAG_SECURE   0x20
#define MEM_FLAG_NOCACHE  0x40
#define MEM_FLAG_GUARD    0x80

// Global MMU context
static MMUContext g_mmu_context;

// Initialize MMU
void init_mmu(void) {
    // Set up translation table base
    uint32_t ttbr0 = (uint32_t)g_mmu_context.page_dir;
    __asm volatile("mcr p15, 0, %0, c2, c0, 0" : : "r" (ttbr0));

    // Set domain access control
    uint32_t domain = 0x55555555; // Client access for all domains
    __asm volatile("mcr p15, 0, %0, c3, c0, 0" : : "r" (domain));

    // Enable MMU
    uint32_t control;
    __asm volatile("mrc p15, 0, %0, c1, c0, 0" : "=r" (control));
    control |= 0x1; // Enable MMU
    control |= 0x4; // Enable data cache
    control |= 0x800; // Enable branch prediction
    control |= 0x1000; // Enable instruction cache
    __asm volatile("mcr p15, 0, %0, c1, c0, 0" : : "r" (control));
}

// Initialize secure memory regions
void init_secure_memory(void) {
    // Set up secure kernel space
    map_secure_region(GHOST_KERNEL_SPACE_START, 
                     GHOST_KERNEL_HEAP_SIZE,
                     MEM_FLAG_KERNEL | MEM_FLAG_SECURE);

    // Set up secure user space regions
    map_secure_region(GHOST_USER_SPACE_START,
                     GHOST_DEFAULT_STACK_SIZE,
                     MEM_FLAG_USER | MEM_FLAG_SECURE);

    // Initialize guard pages
    init_guard_pages();
}

// Map a secure memory region
int map_secure_region(uint32_t virt_addr, uint32_t size, uint32_t flags) {
    // Align addresses to page boundaries
    virt_addr &= ~(GHOST_PAGE_SIZE - 1);
    size = (size + GHOST_PAGE_SIZE - 1) & ~(GHOST_PAGE_SIZE - 1);

    // Allocate physical pages
    uint32_t phys_addr = alloc_physical_pages(size / GHOST_PAGE_SIZE);
    if (!phys_addr) return -1;

    // Create page table entries
    for (uint32_t offset = 0; offset < size; offset += GHOST_PAGE_SIZE) {
        uint32_t virt = virt_addr + offset;
        uint32_t phys = phys_addr + offset;
        
        // Set up page table entry with security flags
        uint32_t pte = phys;
        pte |= (flags & MEM_FLAG_USER) ? 0x20 : 0; // User access
        pte |= (flags & MEM_FLAG_WRITE) ? 0x200 : 0; // Write access
        pte |= (flags & MEM_FLAG_EXEC) ? 0 : 0x1000; // XN bit
        pte |= (flags & MEM_FLAG_SECURE) ? 0x10 : 0; // Secure bit
        
        set_page_table_entry(virt, pte);
    }

    // Add to memory regions list
    if (g_mmu_context.region_count < MAX_MEMORY_REGIONS) {
        MemoryRegion* region = &g_mmu_context.regions[g_mmu_context.region_count++];
        region->virt_addr = virt_addr;
        region->phys_addr = phys_addr;
        region->size = size;
        region->flags = flags;
    }

    return 0;
}

// Initialize guard pages for stack protection
void init_guard_pages(void) {
    // Place guard pages at stack boundaries
    uint32_t stack_start = GHOST_USER_SPACE_START;
    uint32_t stack_end = stack_start + GHOST_DEFAULT_STACK_SIZE;

    // Map guard pages with no access
    map_secure_region(stack_start - GHOST_PAGE_SIZE, GHOST_PAGE_SIZE,
                     MEM_FLAG_GUARD);
    map_secure_region(stack_end, GHOST_PAGE_SIZE,
                     MEM_FLAG_GUARD);
}

// Memory violation handler
void handle_memory_violation(uint32_t fault_addr, uint32_t fault_status) {
    // Check if it's a security violation
    bool is_security_violation = (fault_status & 0x40) != 0;

    if (is_security_violation) {
        // Log security violation
        log_security_event(SECURITY_EVENT_MEMORY_VIOLATION,
                         fault_addr, fault_status);

        // Terminate offending process
        terminate_current_process();
    }

    // Handle other memory faults
    handle_page_fault(fault_addr, fault_status);
}

// Memory protection check
bool check_memory_access(uint32_t addr, uint32_t size, uint32_t required_flags) {
    uint32_t end_addr = addr + size;

    // Check each page in the range
    for (uint32_t curr = addr; curr < end_addr; curr += GHOST_PAGE_SIZE) {
        uint32_t pte = get_page_table_entry(curr);
        uint32_t flags = extract_flags_from_pte(pte);

        if ((flags & required_flags) != required_flags) {
            return false;
        }
    }

    return true;
}

// ASLR implementation
void randomize_kernel_space(void) {
    // Get random offset (implementation specific)
    uint32_t random_offset = get_secure_random() & 0x3FFFFFFF;
    
    // Align to page boundary
    random_offset &= ~(GHOST_PAGE_SIZE - 1);

    // Relocate kernel sections
    relocate_kernel_sections(random_offset);

    // Update page tables
    update_kernel_page_tables(random_offset);
}
