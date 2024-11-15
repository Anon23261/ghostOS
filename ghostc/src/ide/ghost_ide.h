#ifndef GHOST_IDE_H
#define GHOST_IDE_H

#include <stdint.h>
#include <stdbool.h>

// IDE configuration
typedef struct {
    char* workspace_path;
    char* config_file;
    bool dark_mode;
    bool syntax_highlight;
    bool auto_complete;
} IDEConfig;

// Editor buffer
typedef struct {
    char* filename;
    char* content;
    size_t size;
    size_t capacity;
    bool modified;
} EditorBuffer;

// IDE context
typedef struct {
    IDEConfig* config;
    EditorBuffer** buffers;
    size_t buffer_count;
    void* syntax_highlighter;
    void* auto_completer;
    void* debugger;
} IDEContext;

// IDE initialization and cleanup
IDEContext* ghost_ide_init(IDEConfig* config);
void ghost_ide_cleanup(IDEContext* ctx);

// File operations
int ghost_ide_open_file(IDEContext* ctx, const char* filename);
int ghost_ide_save_file(IDEContext* ctx, size_t buffer_id);
int ghost_ide_close_file(IDEContext* ctx, size_t buffer_id);

// Editor operations
int ghost_ide_insert_text(IDEContext* ctx, size_t buffer_id, const char* text, size_t pos);
int ghost_ide_delete_text(IDEContext* ctx, size_t buffer_id, size_t start, size_t end);
char* ghost_ide_get_text(IDEContext* ctx, size_t buffer_id);

// Security features
int ghost_ide_analyze_code(IDEContext* ctx, size_t buffer_id);
int ghost_ide_check_vulnerabilities(IDEContext* ctx, size_t buffer_id);
int ghost_ide_obfuscate_code(IDEContext* ctx, size_t buffer_id);

// Debugging features
int ghost_ide_start_debug(IDEContext* ctx, size_t buffer_id);
int ghost_ide_set_breakpoint(IDEContext* ctx, size_t buffer_id, size_t line);
int ghost_ide_continue_debug(IDEContext* ctx);
int ghost_ide_step_debug(IDEContext* ctx);

// Code analysis
typedef struct {
    char* type;
    size_t line;
    size_t column;
    char* message;
    char* severity;
} CodeIssue;

CodeIssue** ghost_ide_analyze_security(IDEContext* ctx, size_t buffer_id);
void ghost_ide_free_issues(CodeIssue** issues);

#endif // GHOST_IDE_H
