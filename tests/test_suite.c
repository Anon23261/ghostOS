#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "../kernel/src/mm/memory.h"
#include "../bootloader/secure_boot.h"

// Test results tracking
typedef struct {
    const char* test_name;
    bool passed;
    char error_msg[256];
} TestResult;

#define MAX_TESTS 100
static TestResult test_results[MAX_TESTS];
static int test_count = 0;

// Test reporting
void report_test(const char* name, bool passed, const char* msg) {
    if (test_count < MAX_TESTS) {
        test_results[test_count].test_name = name;
        test_results[test_count].passed = passed;
        snprintf(test_results[test_count].error_msg, 256, "%s", msg);
        test_count++;
    }
}

// Memory Management Tests
bool test_memory_allocation(void) {
    // Test basic allocation
    void* ptr = kmalloc(1024, MEM_FLAG_READ | MEM_FLAG_WRITE);
    if (!ptr) {
        report_test("Memory Allocation", false, "Basic allocation failed");
        return false;
    }
    
    // Test memory access
    if (!check_memory_access((uint32_t)ptr, 1024, MEM_FLAG_READ | MEM_FLAG_WRITE)) {
        report_test("Memory Access", false, "Memory access check failed");
        return false;
    }
    
    // Test guard pages
    void* guard_ptr = kmalloc(2048, MEM_FLAG_READ | MEM_FLAG_WRITE | MEM_FLAG_GUARD);
    if (!guard_ptr) {
        report_test("Guard Page Allocation", false, "Guard page allocation failed");
        return false;
    }
    
    // Clean up
    kfree(ptr);
    kfree(guard_ptr);
    
    report_test("Memory Management", true, "All memory tests passed");
    return true;
}

// Secure Boot Tests
bool test_secure_boot(void) {
    // Test secure boot initialization
    if (!secure_boot_init()) {
        report_test("Secure Boot Init", false, "Secure boot initialization failed");
        return false;
    }
    
    // Test kernel signature verification
    int verify_result = verify_kernel_signature();
    if (verify_result != 0) {
        char error[256];
        snprintf(error, sizeof(error), "Kernel signature verification failed: %d", verify_result);
        report_test("Kernel Signature", false, error);
        return false;
    }
    
    // Test runtime integrity
    if (!verify_runtime_integrity()) {
        report_test("Runtime Integrity", false, "Runtime integrity check failed");
        return false;
    }
    
    report_test("Secure Boot", true, "All secure boot tests passed");
    return true;
}

// Security Tests
bool test_security_features(void) {
    // Test memory protection
    void* secure_ptr = kmalloc(512, MEM_FLAG_SECURE | MEM_FLAG_READ);
    if (!secure_ptr) {
        report_test("Secure Memory", false, "Secure memory allocation failed");
        return false;
    }
    
    // Test unauthorized access (should fail)
    bool access_failed = !check_memory_access((uint32_t)secure_ptr, 512, MEM_FLAG_WRITE);
    if (!access_failed) {
        report_test("Memory Protection", false, "Unauthorized write access not prevented");
        return false;
    }
    
    // Clean up
    kfree(secure_ptr);
    
    report_test("Security Features", true, "All security tests passed");
    return true;
}

// Run all tests
void run_all_tests(void) {
    printf("Starting GhostOS Test Suite...\n\n");
    
    // Run tests
    test_memory_allocation();
    test_secure_boot();
    test_security_features();
    
    // Print results
    printf("\nTest Results:\n");
    printf("=============\n");
    
    int passed = 0;
    for (int i = 0; i < test_count; i++) {
        printf("%s: %s\n", test_results[i].test_name,
               test_results[i].passed ? "PASSED" : "FAILED");
        if (!test_results[i].passed) {
            printf("  Error: %s\n", test_results[i].error_msg);
        }
        if (test_results[i].passed) passed++;
    }
    
    printf("\nSummary: %d/%d tests passed\n", passed, test_count);
}
