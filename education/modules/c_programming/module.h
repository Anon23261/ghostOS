#ifndef GHOST_EDUCATION_C_MODULE_H
#define GHOST_EDUCATION_C_MODULE_H

#include <stdint.h>
#include "../../core/learning_framework.h"

// C Programming Learning Module Structure
typedef struct {
    // Module Information
    const char* title;
    const char* description;
    uint32_t difficulty_level;
    
    // Learning Content
    lesson_t* lessons;
    uint32_t lesson_count;
    
    // Practical Exercises
    exercise_t* exercises;
    uint32_t exercise_count;
    
    // Assessment Tools
    assessment_t* assessments;
    uint32_t assessment_count;
    
    // Progress Tracking
    progress_tracker_t progress;
} c_programming_module_t;

// Module Functions
void c_module_init(c_programming_module_t* module);
void c_module_load_lesson(uint32_t lesson_id);
int c_module_run_exercise(uint32_t exercise_id);
assessment_result_t c_module_assess(uint32_t assessment_id);

// Interactive Learning Functions
void c_show_memory_layout(void* ptr, size_t size);
void c_explain_pointer_arithmetic(void* ptr, int offset);
void c_visualize_data_structures(void* structure, size_t size);

// Security-Focused Learning
void c_demonstrate_buffer_overflow(char* buffer, size_t size);
void c_analyze_memory_corruption(void* memory_region);
void c_secure_coding_practice(const char* code_snippet);

#endif // GHOST_EDUCATION_C_MODULE_H
