#ifndef BCM2835_H
#define BCM2835_H

/* BCM2835 Hardware Definitions for Raspberry Pi Zero W */

#define PERIPHERAL_BASE     0x20000000

/* Memory Management Unit */
#define MMU_BASE           (PERIPHERAL_BASE + 0xB000)
#define MMU_ENABLE         (1 << 0)
#define MMU_DISABLE        (0 << 0)

/* System Timer */
#define TIMER_BASE         (PERIPHERAL_BASE + 0x3000)
#define TIMER_CS          *((volatile unsigned int*)(TIMER_BASE + 0x00))
#define TIMER_CLO         *((volatile unsigned int*)(TIMER_BASE + 0x04))
#define TIMER_CHI         *((volatile unsigned int*)(TIMER_BASE + 0x08))
#define TIMER_C0          *((volatile unsigned int*)(TIMER_BASE + 0x0C))
#define TIMER_C1          *((volatile unsigned int*)(TIMER_BASE + 0x10))
#define TIMER_C2          *((volatile unsigned int*)(TIMER_BASE + 0x14))
#define TIMER_C3          *((volatile unsigned int*)(TIMER_BASE + 0x18))

/* GPIO */
#define GPIO_BASE         (PERIPHERAL_BASE + 0x200000)
#define GPFSEL0          *((volatile unsigned int*)(GPIO_BASE + 0x00))
#define GPFSEL1          *((volatile unsigned int*)(GPIO_BASE + 0x04))
#define GPFSEL2          *((volatile unsigned int*)(GPIO_BASE + 0x08))
#define GPFSEL3          *((volatile unsigned int*)(GPIO_BASE + 0x0C))
#define GPFSEL4          *((volatile unsigned int*)(GPIO_BASE + 0x10))
#define GPFSEL5          *((volatile unsigned int*)(GPIO_BASE + 0x14))
#define GPSET0           *((volatile unsigned int*)(GPIO_BASE + 0x1C))
#define GPSET1           *((volatile unsigned int*)(GPIO_BASE + 0x20))
#define GPCLR0           *((volatile unsigned int*)(GPIO_BASE + 0x28))
#define GPCLR1           *((volatile unsigned int*)(GPIO_BASE + 0x2C))
#define GPLEV0           *((volatile unsigned int*)(GPIO_BASE + 0x34))
#define GPLEV1           *((volatile unsigned int*)(GPIO_BASE + 0x38))

/* UART */
#define UART0_BASE        (PERIPHERAL_BASE + 0x201000)
#define UART0_DR         *((volatile unsigned int*)(UART0_BASE + 0x00))
#define UART0_FR         *((volatile unsigned int*)(UART0_BASE + 0x18))
#define UART0_IBRD       *((volatile unsigned int*)(UART0_BASE + 0x24))
#define UART0_FBRD       *((volatile unsigned int*)(UART0_BASE + 0x28))
#define UART0_LCRH       *((volatile unsigned int*)(UART0_BASE + 0x2C))
#define UART0_CR         *((volatile unsigned int*)(UART0_BASE + 0x30))
#define UART0_ICR        *((volatile unsigned int*)(UART0_BASE + 0x44))

/* Memory Map */
#define KERNEL_OFFSET     0x8000
#define KERNEL_MAX_SIZE   (1024 * 1024)  /* 1MB */
#define STACK_SIZE        4096
#define PAGE_SIZE         4096
#define SECURE_BOOT_MAGIC 0x53454355     /* "SECU" */

#endif /* BCM2835_H */
