#ifndef KERNEL_H
#define KERNEL_H

#include <stdint.h>
#include <stddef.h>

/* Kernel Version Information */
#define GHOST_OS_VERSION_MAJOR 0
#define GHOST_OS_VERSION_MINOR 1
#define GHOST_OS_VERSION_PATCH 0

/* Error Codes */
#define GHOST_SUCCESS       0
#define GHOST_ERROR       -1
#define GHOST_NOMEM       -2
#define GHOST_INVALID     -3
#define GHOST_TIMEOUT     -4
#define GHOST_BUSY        -5
#define GHOST_DENIED      -6

/* Process States */
#define PROCESS_READY      0
#define PROCESS_RUNNING    1
#define PROCESS_BLOCKED    2
#define PROCESS_ZOMBIE     3

/* Security Levels */
#define SEC_LEVEL_KERNEL   0
#define SEC_LEVEL_SYSTEM   1
#define SEC_LEVEL_USER     2
#define SEC_LEVEL_APP      3

/* Memory Protection */
#define MEM_READ          (1 << 0)
#define MEM_WRITE         (1 << 1)
#define MEM_EXEC          (1 << 2)
#define MEM_SECURE        (1 << 3)

/* Function Prototypes */
void kernel_init(void);
void kernel_panic(const char* message);
void* kmalloc(size_t size);
void kfree(void* ptr);
int create_process(void (*entry)(void), uint8_t priority);
int schedule_next(void);
void enable_interrupts(void);
void disable_interrupts(void);

#endif /* KERNEL_H */
