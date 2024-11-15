#include "ghost_runtime.h"
#include <stdlib.h>
#include <string.h>

// Secure memory page size
#define GHOST_PAGE_SIZE 4096
#define GHOST_SECURE_POOL_SIZE (1024 * 1024 * 10)  // 10MB secure pool

// Internal functions
static void* create_secure_heap(size_t size);
static void destroy_secure_heap(void* heap);
static bool setup_memory_protection(void);

GhostRuntime* ghost_runtime_init(uint32_t flags) {
    GhostRuntime* rt = (GhostRuntime*)calloc(1, sizeof(GhostRuntime));
    if (!rt) return NULL;

    rt->flags = flags;

    // Initialize secure heap
    if (flags & GHOST_RT_SECURE_MODE) {
        rt->secure_heap = create_secure_heap(GHOST_SECURE_POOL_SIZE);
        if (!rt->secure_heap) {
            free(rt);
            return NULL;
        }
    }

    // Initialize encrypted memory region
    rt->encrypted_memory = ghost_rt_secure_alloc(rt, GHOST_PAGE_SIZE);
    if (!rt->encrypted_memory) {
        destroy_secure_heap(rt->secure_heap);
        free(rt);
        return NULL;
    }

    // Initialize hook table
    rt->hooks_table = ghost_rt_alloc(rt, sizeof(void*) * 1024);
    if (!rt->hooks_table) {
        ghost_rt_secure_free(rt, rt->encrypted_memory);
        destroy_secure_heap(rt->secure_heap);
        free(rt);
        return NULL;
    }

    // Initialize process and network tables
    rt->process_table = ghost_rt_alloc(rt, sizeof(void*) * 256);
    rt->network_table = ghost_rt_alloc(rt, sizeof(void*) * 256);

    // Setup memory protection
    if (!setup_memory_protection()) {
        ghost_runtime_cleanup(rt);
        return NULL;
    }

    return rt;
}

void ghost_runtime_cleanup(GhostRuntime* rt) {
    if (!rt) return;

    // Remove hooks before cleanup
    ghost_rt_remove_hooks(rt);

    // Free secure memory
    if (rt->encrypted_memory) {
        ghost_rt_secure_free(rt, rt->encrypted_memory);
    }

    // Free tables
    if (rt->hooks_table) ghost_rt_free(rt, rt->hooks_table);
    if (rt->process_table) ghost_rt_free(rt, rt->process_table);
    if (rt->network_table) ghost_rt_free(rt, rt->network_table);

    // Destroy secure heap
    if (rt->secure_heap) {
        destroy_secure_heap(rt->secure_heap);
    }

    // Clear and free runtime context
    memset(rt, 0, sizeof(GhostRuntime));
    free(rt);
}

void* ghost_rt_alloc(GhostRuntime* rt, size_t size) {
    if (!rt || size == 0) return NULL;
    return calloc(1, size);
}

void ghost_rt_free(GhostRuntime* rt, void* ptr) {
    if (!rt || !ptr) return;
    memset(ptr, 0, _msize(ptr));  // Secure cleanup
    free(ptr);
}

void* ghost_rt_secure_alloc(GhostRuntime* rt, size_t size) {
    if (!rt || !rt->secure_heap || size == 0) return NULL;
    
    // Align size to page boundary
    size = (size + GHOST_PAGE_SIZE - 1) & ~(GHOST_PAGE_SIZE - 1);
    
    // Allocate from secure heap
    void* ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ptr) return NULL;

    // Lock pages in memory
    VirtualLock(ptr, size);
    
    return ptr;
}

void ghost_rt_secure_free(GhostRuntime* rt, void* ptr) {
    if (!rt || !ptr) return;
    
    size_t size = VirtualQuerySize(ptr);
    if (size > 0) {
        // Secure cleanup
        memset(ptr, 0, size);
        VirtualUnlock(ptr, size);
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
}

// Internal function implementations
static void* create_secure_heap(size_t size) {
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

static void destroy_secure_heap(void* heap) {
    if (heap) {
        VirtualFree(heap, 0, MEM_RELEASE);
    }
}

static bool setup_memory_protection(void) {
    // Enable DEP
    DWORD flags = PROCESS_DEP_ENABLE | PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION;
    return SetProcessDEPPolicy(flags);
}
