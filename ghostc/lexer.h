#ifndef GHOSTC_LEXER_H
#define GHOSTC_LEXER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Token types
typedef enum {
    TOKEN_EOF = 0,
    TOKEN_IDENTIFIER,
    TOKEN_NUMBER,
    TOKEN_STRING,
    TOKEN_PLUS,
    TOKEN_MINUS,
    TOKEN_STAR,
    TOKEN_SLASH,
    TOKEN_EQUAL,
    TOKEN_LPAREN,
    TOKEN_RPAREN,
    TOKEN_LBRACE,
    TOKEN_RBRACE,
    TOKEN_SEMICOLON,
    TOKEN_KEYWORD,
    TOKEN_HEX,           // For shellcode and exploits
    TOKEN_BYTES,         // For raw byte manipulation
    TOKEN_NETWORK,       // For network operations
    TOKEN_PORT,          // For port numbers
    TOKEN_IP,            // For IP addresses
    TOKEN_SHELLCODE,     // For shellcode operations
    TOKEN_PAYLOAD,       // For payload definitions
    TOKEN_ERROR
} TokenType;

// Keywords
typedef enum {
    KW_FUNC,
    KW_VAR,
    KW_IF,
    KW_ELSE,
    KW_WHILE,
    KW_RETURN,
    KW_SECURE,
    KW_SANDBOX,
    // Security-focused keywords
    KW_EXPLOIT,          // For exploit development
    KW_PAYLOAD,          // For payload creation
    KW_SCAN,            // For network scanning
    KW_INJECT,          // For code injection
    KW_SHELLCODE,       // For shellcode operations
    KW_LISTEN,          // For creating listeners
    KW_CONNECT,         // For network connections
    KW_ENCRYPT,         // For encryption operations
    KW_DECRYPT,         // For decryption operations
    KW_OBFUSCATE,       // For code obfuscation
    KW_DEOBFUSCATE,     // For code deobfuscation
    KW_ANALYZE,         // For malware analysis
    KW_SANDBOX_DETECT,  // For sandbox detection
    KW_PERSIST,         // For persistence mechanisms
    KW_HIDE,            // For stealth operations
    KW_ELEVATE,         // For privilege escalation
    KW_HOOK,            // For API hooking
    KW_UNHOOK,          // For API unhooking
    KW_DUMP,            // For memory dumping
    KW_PATCH            // For binary patching
} KeywordType;

// Token structure
typedef struct {
    TokenType type;
    char* value;
    int line;
    int column;
} Token;

// Lexer structure
typedef struct {
    char* source;
    size_t source_len;
    size_t current;
    size_t line;
    size_t column;
} Lexer;

// Lexer functions
Lexer* lexer_create(const char* source);
void lexer_destroy(Lexer* lexer);
Token* lexer_next_token(Lexer* lexer);
void token_destroy(Token* token);

#endif // GHOSTC_LEXER_H
