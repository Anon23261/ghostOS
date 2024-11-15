#ifndef GHOSTOS_SECURITY_H
#define GHOSTOS_SECURITY_H

#include <stdint.h>

// Security Subsystem Initialization
void security_init(void);
void memory_protection_init(void);
void secure_boot_verify(void);

// Memory Protection
int memory_protect_region(void* addr, size_t size, uint32_t permissions);
int memory_unprotect_region(void* addr, size_t size);

// Process Security
int process_verify_signature(const void* process_image, size_t size);
int process_set_security_level(pid_t pid, uint32_t security_level);

// Network Security
int network_enable_encryption(void);
int network_set_firewall_rules(const firewall_rule_t* rules, size_t count);

// Threat Detection
void threat_detection_init(void);
int threat_register_callback(threat_callback_t callback);
void threat_scan_memory(void* addr, size_t size);

// Security Audit
void audit_log_event(const char* event, uint32_t severity);
void audit_enable_logging(void);
void audit_disable_logging(void);

#endif // GHOSTOS_SECURITY_H
