#ifndef GHOST_IDE_H
#define GHOST_IDE_H

#include <stdint.h>
#include <stdbool.h>
#include "ghost_security.h"

// IDE Security Flags
#define IDE_SEC_ENCRYPTED      0x01
#define IDE_SEC_ANONYMOUS      0x02
#define IDE_SEC_SANDBOXED     0x04
#define IDE_SEC_STEALTH       0x08
#define IDE_SEC_ANTI_DEBUG    0x10

// Malware Types
typedef enum {
    MALWARE_TYPE_ROOTKIT,
    MALWARE_TYPE_RANSOMWARE,
    MALWARE_TYPE_BOTNET,
    MALWARE_TYPE_WORM,
    MALWARE_TYPE_TROJAN,
    MALWARE_TYPE_BACKDOOR,
    MALWARE_TYPE_KEYLOGGER
} MalwareType;

// Project Configuration
typedef struct {
    char name[256];
    MalwareType type;
    uint32_t security_flags;
    uint32_t target_arch;
    uint32_t target_os;
    bool anti_analysis;
    bool anti_debugging;
    bool anti_vm;
    bool encrypted_comms;
} ProjectConfig;

// Editor State
typedef struct {
    char* buffer;
    size_t size;
    size_t capacity;
    uint32_t cursor_pos;
    uint32_t selection_start;
    uint32_t selection_end;
    bool is_modified;
} EditorState;

// Analysis Results
typedef struct {
    uint32_t vulnerability_count;
    uint32_t security_score;
    char** warnings;
    char** suggestions;
    bool has_critical_issues;
} CodeAnalysis;

// Core IDE Functions
void init_ghost_ide(void);
ProjectConfig* create_malware_project(const char* name, MalwareType type);
CodeAnalysis* analyze_code(const char* code);
bool compile_malware(const char* code, const char* output_path);

// Template Generation
char* generate_malware_template(MalwareType type);
void add_anti_analysis_code(char* template);
void add_encryption_layer(char* template);
void add_code_obfuscation(char* template);

// Security Features
void add_anti_analysis_features(char* code);
void setup_secure_communication(void);
char* obfuscate_code(const char* code);
void cleanup_ide_environment(void);

#endif // GHOST_IDE_H
