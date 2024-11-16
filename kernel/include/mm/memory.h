#ifndef MEMORY_H
#define MEMORY_H

#include <stdint.h>
#include <stddef.h>

/* Memory Management Structures */
typedef struct {
    uint32_t virt_addr;
    uint32_t phys_addr;
    uint32_t size;
    uint32_t flags;
} memory_region_t;

typedef struct {
    uint32_t total_memory;
    uint32_t free_memory;
    uint32_t used_memory;
    uint32_t reserved_memory;
} memory_stats_t;

/* Memory Management Functions */
void mm_init(void);
void* mm_alloc_page(void);
void mm_free_page(void* page);
int mm_map_region(memory_region_t* region);
int mm_unmap_region(memory_region_t* region);
void mm_get_stats(memory_stats_t* stats);

/* Memory Protection */
int mm_set_protection(void* addr, size_t size, uint32_t flags);
int mm_verify_access(void* addr, size_t size, uint32_t flags);

/* Secure Memory Functions */
void* mm_alloc_secure(size_t size);
void mm_free_secure(void* ptr);
int mm_verify_secure(void* addr, size_t size);

#endif /* MEMORY_H */
