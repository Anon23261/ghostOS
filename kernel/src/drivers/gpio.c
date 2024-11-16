#include <stdint.h>
#include "../include/gpio.h"

// BCM2835 GPIO registers for Raspberry Pi Zero W
#define GPIO_BASE       0x20200000
#define GPFSEL0         ((volatile uint32_t*)(GPIO_BASE + 0x00))
#define GPSET0          ((volatile uint32_t*)(GPIO_BASE + 0x1C))
#define GPCLR0          ((volatile uint32_t*)(GPIO_BASE + 0x28))

void gpio_init(void) {
    // Initialize GPIO controller
    // Implementation specific to RPi Zero W
}

void gpio_set_function(uint8_t pin, gpio_function_t function) {
    volatile uint32_t* gpfsel = GPFSEL0 + (pin / 10);
    uint8_t shift = (pin % 10) * 3;
    uint32_t mask = 0b111 << shift;
    uint32_t value = function << shift;
    
    *gpfsel = (*gpfsel & ~mask) | value;
}

void gpio_set(uint8_t pin) {
    GPSET0[pin / 32] = 1 << (pin % 32);
}

void gpio_clear(uint8_t pin) {
    GPCLR0[pin / 32] = 1 << (pin % 32);
}
