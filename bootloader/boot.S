.section ".text.boot"

.global _start

_start:
    // Disable interrupts during boot
    cpsid if
    
    // Check processor ID is zero (primary core)
    mrc p15, 0, r1, c0, c0, 5
    and r1, r1, #3
    cmp r1, #0
    bne halt
    
    // Setup the stack
    ldr r1, =_start
    mov sp, r1
    
    // Clear BSS
    ldr r4, =__bss_start
    ldr r9, =__bss_end
    mov r5, #0
    mov r6, #0
    mov r7, #0
    mov r8, #0
    b 2f

1:
    // Store multiple at r4
    stmia r4!, {r5-r8}

2:
    // Loop until we hit the end
    cmp r4, r9
    blo 1b

    // Initialize security features
    bl secure_boot_init
    
    // Verify kernel signature
    bl verify_kernel_signature
    
    // Jump to kernel if verification passed
    ldr r3, =kernel_main
    blx r3

halt:
    wfe
    b halt
