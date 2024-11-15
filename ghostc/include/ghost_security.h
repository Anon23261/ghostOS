#ifndef GHOST_SECURITY_H
#define GHOST_SECURITY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Network Operations
typedef struct {
    char* target;
    uint16_t start_port;
    uint16_t end_port;
    uint32_t timeout;
    bool stealth;
} ScanConfig;

typedef struct {
    char* type;
    char* target;
    bool encrypt;
    bool obfuscate;
    bool sandbox_detect;
} PayloadConfig;

// Exploit Development
typedef struct {
    char* target;
    char* type;
    uint8_t* shellcode;
    size_t shellcode_size;
    char* pattern;
    size_t pattern_size;
} ExploitConfig;

// Malware Analysis
typedef struct {
    char* target_file;
    bool sandbox;
    bool detect_anti_debug;
    bool trace_api_calls;
    bool dump_memory;
} AnalysisConfig;

// Process Operations
typedef struct {
    uint32_t target_pid;
    uint8_t* payload;
    size_t payload_size;
    char* method;
    bool elevate;
    bool hide;
} InjectConfig;

// Network Listener
typedef struct {
    uint16_t port;
    char* type;
    bool persist;
    bool hide;
} ListenerConfig;

// Security Functions
int ghost_scan_ports(ScanConfig* config);
int ghost_create_payload(PayloadConfig* config);
int ghost_run_exploit(ExploitConfig* config);
int ghost_analyze_malware(AnalysisConfig* config);
int ghost_inject_process(InjectConfig* config);
int ghost_create_listener(ListenerConfig* config);

// Memory Operations
void* ghost_allocate_secure(size_t size);
void ghost_free_secure(void* ptr);
int ghost_protect_memory(void* addr, size_t size, int protection);

// Encryption Operations
int ghost_encrypt_buffer(uint8_t* data, size_t size, char* key);
int ghost_decrypt_buffer(uint8_t* data, size_t size, char* key);

// Anti-Analysis Features
bool ghost_detect_debugger(void);
bool ghost_detect_virtualization(void);
bool ghost_detect_sandbox(void);

// Stealth Operations
int ghost_hide_process(uint32_t pid);
int ghost_hide_file(char* path);
int ghost_hide_network(uint16_t port);

// API Hooking
int ghost_hook_api(char* module, char* function, void* hook);
int ghost_unhook_api(char* module, char* function);

// Process Elevation
int ghost_elevate_privileges(void);
int ghost_impersonate_token(uint32_t pid);

#endif // GHOST_SECURITY_H
