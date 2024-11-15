#ifndef GHOST_RUNTIME_H
#define GHOST_RUNTIME_H

#include <stdint.h>
#include <stdbool.h>
#include "../include/ghost_security.h"

// Runtime initialization flags
#define GHOST_RT_SECURE_MODE     0x0001
#define GHOST_RT_STEALTH_MODE    0x0002
#define GHOST_RT_DEBUG_MODE      0x0004
#define GHOST_RT_SANDBOX_MODE    0x0008

// Runtime context structure
typedef struct {
    uint32_t flags;
    void* secure_heap;
    void* encrypted_memory;
    void* hooks_table;
    void* process_table;
    void* network_table;
} GhostRuntime;

// Runtime initialization and cleanup
GhostRuntime* ghost_runtime_init(uint32_t flags);
void ghost_runtime_cleanup(GhostRuntime* rt);

// Memory management
void* ghost_rt_alloc(GhostRuntime* rt, size_t size);
void ghost_rt_free(GhostRuntime* rt, void* ptr);
void* ghost_rt_secure_alloc(GhostRuntime* rt, size_t size);
void ghost_rt_secure_free(GhostRuntime* rt, void* ptr);

// Process management
int ghost_rt_attach_process(GhostRuntime* rt, uint32_t pid);
int ghost_rt_detach_process(GhostRuntime* rt, uint32_t pid);
int ghost_rt_inject_payload(GhostRuntime* rt, InjectConfig* config);

// Network operations
int ghost_rt_init_network(GhostRuntime* rt);
int ghost_rt_create_listener(GhostRuntime* rt, ListenerConfig* config);
int ghost_rt_scan_ports(GhostRuntime* rt, ScanConfig* config);

// Security operations
int ghost_rt_install_hooks(GhostRuntime* rt);
int ghost_rt_remove_hooks(GhostRuntime* rt);
bool ghost_rt_check_security(GhostRuntime* rt);

#endif // GHOST_RUNTIME_H
