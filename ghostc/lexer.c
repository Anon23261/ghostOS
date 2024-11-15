#include "lexer.h"

// Keywords table
static const char* KEYWORDS[] = {
    "func",
    "var",
    "if",
    "else",
    "while",
    "return",
    "secure",
    "sandbox",
    // Security keywords
    "exploit",
    "payload",
    "scan",
    "inject",
    "shellcode",
    "listen",
    "connect",
    "encrypt",
    "decrypt",
    "obfuscate",
    "deobfuscate",
    "analyze",
    "sandbox_detect",
    "persist",
    "hide",
    "elevate",
    "hook",
    "unhook",
    "dump",
    "patch"
};

Lexer* lexer_create(const char* source) {
    Lexer* lexer = (Lexer*)malloc(sizeof(Lexer));
    if (!lexer) return NULL;
    
    lexer->source = strdup(source);
    lexer->source_len = strlen(source);
    lexer->current = 0;
    lexer->line = 1;
    lexer->column = 1;
    
    return lexer;
}

void lexer_destroy(Lexer* lexer) {
    if (lexer) {
        free(lexer->source);
        free(lexer);
    }
}

static int is_keyword(const char* str) {
    for (size_t i = 0; i < sizeof(KEYWORDS) / sizeof(KEYWORDS[0]); i++) {
        if (strcmp(str, KEYWORDS[i]) == 0) {
            return i;
        }
    }
    return -1;
}

static char peek(Lexer* lexer) {
    if (lexer->current >= lexer->source_len) return '\0';
    return lexer->source[lexer->current];
}

static char advance(Lexer* lexer) {
    char c = peek(lexer);
    if (c != '\0') {
        lexer->current++;
        lexer->column++;
        if (c == '\n') {
            lexer->line++;
            lexer->column = 1;
        }
    }
    return c;
}

static Token* create_token(TokenType type, const char* value, int line, int column) {
    Token* token = (Token*)malloc(sizeof(Token));
    if (!token) return NULL;
    
    token->type = type;
    token->value = value ? strdup(value) : NULL;
    token->line = line;
    token->column = column;
    
    return token;
}

Token* lexer_next_token(Lexer* lexer) {
    // Skip whitespace and comments
    while (1) {
        char c = peek(lexer);
        if (isspace(c)) {
            advance(lexer);
            continue;
        }
        if (c == '/' && lexer->current + 1 < lexer->source_len) {
            if (lexer->source[lexer->current + 1] == '/') {
                // Skip single-line comment
                while (peek(lexer) != '\n' && peek(lexer) != '\0') {
                    advance(lexer);
                }
                continue;
            }
            if (lexer->source[lexer->current + 1] == '*') {
                // Skip multi-line comment
                advance(lexer); // Skip '/'
                advance(lexer); // Skip '*'
                while (peek(lexer) != '\0') {
                    if (peek(lexer) == '*' && 
                        lexer->current + 1 < lexer->source_len &&
                        lexer->source[lexer->current + 1] == '/') {
                        advance(lexer); // Skip '*'
                        advance(lexer); // Skip '/'
                        break;
                    }
                    advance(lexer);
                }
                continue;
            }
        }
        break;
    }
    
    char c = peek(lexer);
    int start_column = lexer->column;
    
    if (c == '\0') {
        return create_token(TOKEN_EOF, NULL, lexer->line, start_column);
    }
    
    // Handle hex numbers (for shellcode)
    if (c == '0' && lexer->current + 1 < lexer->source_len &&
        (lexer->source[lexer->current + 1] == 'x' || 
         lexer->source[lexer->current + 1] == 'X')) {
        size_t start = lexer->current;
        advance(lexer); // Skip '0'
        advance(lexer); // Skip 'x'
        
        while (isxdigit(peek(lexer))) {
            advance(lexer);
        }
        
        size_t length = lexer->current - start;
        char* value = (char*)malloc(length + 1);
        strncpy(value, lexer->source + start, length);
        value[length] = '\0';
        
        Token* token = create_token(TOKEN_HEX, value, lexer->line, start_column);
        free(value);
        return token;
    }
    
    // Handle network addresses (simple IPv4)
    if (isdigit(c) && strchr(lexer->source + lexer->current, '.')) {
        size_t start = lexer->current;
        int dots = 0;
        
        while ((isdigit(peek(lexer)) || peek(lexer) == '.') && dots < 4) {
            if (peek(lexer) == '.') dots++;
            advance(lexer);
        }
        
        if (dots == 3) {
            size_t length = lexer->current - start;
            char* value = (char*)malloc(length + 1);
            strncpy(value, lexer->source + start, length);
            value[length] = '\0';
            
            Token* token = create_token(TOKEN_IP, value, lexer->line, start_column);
            free(value);
            return token;
        }
        
        // Reset if not a valid IP
        lexer->current = start;
    }
    
    // Handle port numbers
    if (c == ':' && isdigit(lexer->source[lexer->current + 1])) {
        advance(lexer); // Skip ':'
        size_t start = lexer->current;
        
        while (isdigit(peek(lexer))) {
            advance(lexer);
        }
        
        size_t length = lexer->current - start;
        char* value = (char*)malloc(length + 1);
        strncpy(value, lexer->source + start, length);
        value[length] = '\0';
        
        Token* token = create_token(TOKEN_PORT, value, lexer->line, start_column);
        free(value);
        return token;
    }
    
    // Handle identifiers and keywords
    if (isalpha(c) || c == '_') {
        size_t start = lexer->current;
        while (isalnum(peek(lexer)) || peek(lexer) == '_') {
            advance(lexer);
        }
        
        size_t length = lexer->current - start;
        char* value = (char*)malloc(length + 1);
        strncpy(value, lexer->source + start, length);
        value[length] = '\0';
        
        int keyword_index = is_keyword(value);
        if (keyword_index >= 0) {
            Token* token = create_token(TOKEN_KEYWORD, value, lexer->line, start_column);
            free(value);
            return token;
        } else {
            Token* token = create_token(TOKEN_IDENTIFIER, value, lexer->line, start_column);
            free(value);
            return token;
        }
    }
    
    // Handle numbers
    if (isdigit(c)) {
        size_t start = lexer->current;
        while (isdigit(peek(lexer))) {
            advance(lexer);
        }
        
        size_t length = lexer->current - start;
        char* value = (char*)malloc(length + 1);
        strncpy(value, lexer->source + start, length);
        value[length] = '\0';
        
        Token* token = create_token(TOKEN_NUMBER, value, lexer->line, start_column);
        free(value);
        return token;
    }
    
    // Handle single-character tokens
    advance(lexer);
    switch (c) {
        case '+': return create_token(TOKEN_PLUS, "+", lexer->line, start_column);
        case '-': return create_token(TOKEN_MINUS, "-", lexer->line, start_column);
        case '*': return create_token(TOKEN_STAR, "*", lexer->line, start_column);
        case '/': return create_token(TOKEN_SLASH, "/", lexer->line, start_column);
        case '=': return create_token(TOKEN_EQUAL, "=", lexer->line, start_column);
        case '(': return create_token(TOKEN_LPAREN, "(", lexer->line, start_column);
        case ')': return create_token(TOKEN_RPAREN, ")", lexer->line, start_column);
        case '{': return create_token(TOKEN_LBRACE, "{", lexer->line, start_column);
        case '}': return create_token(TOKEN_RBRACE, "}", lexer->line, start_column);
        case ';': return create_token(TOKEN_SEMICOLON, ";", lexer->line, start_column);
        default:
            return create_token(TOKEN_ERROR, NULL, lexer->line, start_column);
    }
}

void token_destroy(Token* token) {
    if (token) {
        free(token->value);
        free(token);
    }
}
