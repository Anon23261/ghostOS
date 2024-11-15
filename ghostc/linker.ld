/* Linker script for GhostC IDE (ARM Cortex-M0) */

MEMORY
{
    FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 256K
    RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 32K
}

ENTRY(Reset_Handler)

SECTIONS
{
    .text :
    {
        KEEP(*(.isr_vector))
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
        _etext = .;
    } > FLASH

    .data :
    {
        _sdata = .;
        *(.data*)
        . = ALIGN(4);
        _edata = .;
    } > RAM AT > FLASH

    .bss :
    {
        _sbss = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = .;
    } > RAM

    .heap :
    {
        __heap_start__ = .;
        . = . + 16K;
        __heap_end__ = .;
    } > RAM

    .stack :
    {
        . = ALIGN(8);
        __stack_start__ = .;
        . = . + 4K;
        . = ALIGN(8);
        __stack_end__ = .;
    } > RAM
}
