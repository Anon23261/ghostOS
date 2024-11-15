#ifndef GHOST_C_MODULE_01_H
#define GHOST_C_MODULE_01_H

#include "../../core/course_base.h"
#include "../../core/interactive_shell.h"
#include "../../core/security_sandbox.h"

// Module 1: C Programming Fundamentals
typedef struct {
    // Week 1: Introduction to C and Security Mindset
    struct {
        // Day 1: Setup and Introduction
        struct {
            void (*setup_environment)(void);
            void (*intro_to_compiler)(void);
            void (*first_program)(void);
            // Hands-on Lab: Building and running first secure program
            lab_exercise_t first_program_lab;
        } day1;

        // Day 2: Variables and Data Types
        struct {
            void (*basic_types)(void);
            void (*memory_representation)(void);
            void (*secure_initialization)(void);
            // Lab: Memory layout visualization
            lab_exercise_t memory_lab;
        } day2;

        // Day 3: Operators and Expressions
        struct {
            void (*arithmetic_ops)(void);
            void (*bitwise_ops)(void);
            void (*secure_operations)(void);
            // Lab: Implementing basic encryption
            lab_exercise_t crypto_lab;
        } day3;

        // Day 4: Control Flow
        struct {
            void (*conditions)(void);
            void (*loops)(void);
            void (*secure_branching)(void);
            // Lab: Input validation patterns
            lab_exercise_t validation_lab;
        } day4;

        // Day 5: Functions
        struct {
            void (*function_basics)(void);
            void (*parameter_passing)(void);
            void (*secure_functions)(void);
            // Lab: Building secure utility functions
            lab_exercise_t functions_lab;
        } day5;

        // Weekend Project
        struct {
            // Build a secure command-line tool
            project_t secure_cli_project;
            // Code review session
            void (*code_review)(void);
            // Security assessment
            void (*security_check)(void);
        } weekend;
    } week1;

    // Assessment and Progress Tracking
    struct {
        // Daily Quizzes
        quiz_t daily_quizzes[5];
        // Hands-on Labs
        lab_result_t lab_results[5];
        // Weekend Project Evaluation
        project_evaluation_t project_eval;
        // Security Knowledge Assessment
        security_eval_t security_eval;
    } assessment;

    // Interactive Learning Tools
    struct {
        // Code Visualization
        void (*visualize_memory)(void* ptr, size_t size);
        void (*show_stack_frame)(void);
        // Debugging Tools
        void (*debug_exercise)(const char* exercise_name);
        void (*memory_check)(void);
        // Security Analysis
        void (*analyze_vulnerabilities)(const char* code);
        void (*suggest_improvements)(void);
    } tools;

    // Resources and References
    struct {
        // Documentation
        const char* (*get_topic_docs)(const char* topic);
        // Example Code
        const char* (*get_secure_examples)(const char* concept);
        // Additional Reading
        const char* (*get_security_papers)(const char* topic);
        // Video Tutorials
        const char* (*get_video_tutorial)(const char* topic);
    } resources;

    // Hands-on Projects
    struct {
        // Mini-Projects
        project_t daily_projects[5];
        // Security Exercises
        security_exercise_t security_tasks[5];
        // Code Review Tasks
        review_task_t code_reviews[5];
        // Integration Project
        project_t week_project;
    } projects;
} c_module_01_t;

// Module Functions
void module_01_init(void);
void start_daily_lesson(uint32_t day);
void submit_lab_work(const char* lab_name, const char* code);
void request_code_review(const char* code);

// Progress Tracking
void view_progress(void);
void get_daily_feedback(void);
void review_weak_areas(void);

// Interactive Features
void join_live_session(void);
void ask_question(const char* question);
void share_code(const char* code);

// Security Training
void practice_secure_coding(void);
void analyze_vulnerability(const char* code);
void verify_fix(const char* original, const char* fixed);

#endif // GHOST_C_MODULE_01_H
