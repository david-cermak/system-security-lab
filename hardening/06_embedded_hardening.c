/*
 * 06_embedded_hardening.c - Hardening for bare-metal / RTOS / embedded
 *
 * Paper context: The paper's defenses (memory permissions, stack guards,
 * allocator hardening) are even MORE critical in embedded systems because:
 *
 *   1. No MMU = No ASLR = Every address is deterministic
 *   2. No process isolation = One bug compromises everything
 *   3. Limited tooling = Bugs persist longer in the field
 *   4. Physical access = Side channels are trivially exploitable
 *   5. Long deployment lifetimes = Vulnerabilities accumulate
 *
 * This file demonstrates embedded-relevant hardening patterns that
 * don't require an OS or MMU. These compile on any system but model
 * patterns used in bare-metal firmware.
 *
 * Compile:
 *   gcc -O2 -Wall -Wextra -o 06_embedded 06_embedded_hardening.c
 *
 * For actual embedded cross-compilation (ARM Cortex-M example):
 *   arm-none-eabi-gcc -mcpu=cortex-m4 -mthumb -O2 \
 *       -fstack-protector-strong -fstack-usage \
 *       -Wstack-usage=256 \
 *       -c 06_embedded_hardening.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* ================================================================
 * Pattern 1: Stack Painting (canary without OS support)
 *
 * On bare-metal systems without CONFIG_STACKPROTECTOR, you can
 * "paint" the stack with a known pattern at startup and periodically
 * check for corruption. This is the embedded equivalent of the
 * kernel's stack canary.
 * ================================================================ */

#define STACK_PAINT_PATTERN 0xDEADC0DE
#define STACK_SIZE 1024

static uint32_t fake_stack[STACK_SIZE];

static void stack_paint_init(void) {
    for (size_t i = 0; i < STACK_SIZE; i++) {
        fake_stack[i] = STACK_PAINT_PATTERN;
    }
}

static size_t stack_paint_check(void) {
    size_t high_water = 0;
    for (size_t i = 0; i < STACK_SIZE; i++) {
        if (fake_stack[i] != STACK_PAINT_PATTERN) {
            high_water = STACK_SIZE - i;
            break;
        }
    }
    return high_water;
}

static void demo_stack_painting(void) {
    printf("[1] Stack Painting (bare-metal stack overflow detection):\n");

    stack_paint_init();
    printf("  Stack painted with 0x%08X (%zu uint32_t words)\n",
           STACK_PAINT_PATTERN, (size_t)STACK_SIZE);

    /* Simulate stack usage by corrupting from the "top" */
    for (int i = STACK_SIZE - 1; i >= STACK_SIZE - 100; i--) {
        fake_stack[i] = 0x41414141;  /* simulate stack frame */
    }

    size_t used = stack_paint_check();
    printf("  Stack high-water mark: %zu words (%zu bytes)\n",
           used, used * sizeof(uint32_t));
    printf("  Remaining: %zu words\n", STACK_SIZE - used);

    if (used > STACK_SIZE * 3 / 4) {
        printf("  [WARNING] Stack usage > 75%%! Overflow risk.\n");
    }
    printf("  This is how FreeRTOS uxTaskGetStackHighWaterMark() works.\n");
}

/* ================================================================
 * Pattern 2: Pool Allocator with Canaries
 *
 * Embedded systems often use pool allocators (fixed-size blocks).
 * Adding canaries to each block detects heap corruption, similar
 * to CONFIG_SLAB_FREELIST_HARDENED in the kernel.
 * ================================================================ */

#define POOL_BLOCK_SIZE  64
#define POOL_BLOCK_COUNT 16
#define POOL_CANARY      0xBADDF00D

struct pool_block {
    uint32_t canary_head;
    uint8_t  data[POOL_BLOCK_SIZE];
    uint32_t canary_tail;
    bool     in_use;
};

static struct pool_block pool[POOL_BLOCK_COUNT];

static void pool_init(void) {
    for (int i = 0; i < POOL_BLOCK_COUNT; i++) {
        pool[i].canary_head = POOL_CANARY;
        pool[i].canary_tail = POOL_CANARY;
        pool[i].in_use = false;
        memset(pool[i].data, 0, POOL_BLOCK_SIZE);
    }
}

static void *pool_alloc(void) {
    for (int i = 0; i < POOL_BLOCK_COUNT; i++) {
        if (!pool[i].in_use) {
            pool[i].in_use = true;
            return pool[i].data;
        }
    }
    return NULL;  /* pool exhausted */
}

static bool pool_free(void *ptr) {
    for (int i = 0; i < POOL_BLOCK_COUNT; i++) {
        if (pool[i].data == ptr) {
            /* Check canaries before free -- detect corruption */
            if (pool[i].canary_head != POOL_CANARY ||
                pool[i].canary_tail != POOL_CANARY) {
                printf("  [CORRUPTION] Block %d canary violated!\n", i);
                printf("  head: 0x%08X (expect 0x%08X)\n",
                       pool[i].canary_head, POOL_CANARY);
                printf("  tail: 0x%08X (expect 0x%08X)\n",
                       pool[i].canary_tail, POOL_CANARY);
                return false;  /* corruption detected */
            }
            /* Clear on free (like CONFIG_INIT_ON_FREE_DEFAULT_ON) */
            memset(pool[i].data, 0, POOL_BLOCK_SIZE);
            pool[i].in_use = false;
            return true;
        }
    }
    return false;  /* invalid pointer */
}

static int pool_check_integrity(void) {
    int corrupted = 0;
    for (int i = 0; i < POOL_BLOCK_COUNT; i++) {
        if (pool[i].canary_head != POOL_CANARY ||
            pool[i].canary_tail != POOL_CANARY) {
            corrupted++;
        }
    }
    return corrupted;
}

static void demo_pool_allocator(void) {
    printf("\n[2] Pool Allocator with Canaries (embedded heap hardening):\n");

    pool_init();

    /* Normal usage */
    uint8_t *block = pool_alloc();
    printf("  Allocated block at %p\n", (void *)block);
    memcpy(block, "safe data", 9);
    printf("  Written: '%s'\n", (char *)block);

    /* Simulate an overflow (write past block boundary into canary) */
    printf("\n  Simulating buffer overflow (writing 70 bytes to 64-byte block)...\n");
    memset(block, 'A', 70);  /* Overwrites canary_tail! */

    /* Detection: check canary on free */
    bool ok = pool_free(block);
    printf("  pool_free returned: %s\n", ok ? "OK" : "CORRUPTION DETECTED");

    int bad = pool_check_integrity();
    printf("  Integrity check: %d corrupted block(s)\n", bad);
}

/* ================================================================
 * Pattern 3: MPU-style W^X in Software
 *
 * The paper discusses CONFIG_STRICT_*_RWX (no writable+executable
 * memory). On Cortex-M with MPU, you can enforce this in hardware.
 * Without MPU, you can at least validate function pointers.
 * ================================================================ */

/* Simple function pointer validation table */
typedef void (*handler_t)(void);

static void handler_a(void) { printf("  Handler A executed\n"); }
static void handler_b(void) { printf("  Handler B executed\n"); }
static void handler_c(void) { printf("  Handler C executed\n"); }

static const handler_t valid_handlers[] = {
    handler_a,
    handler_b,
    handler_c,
    NULL  /* sentinel */
};

static bool validate_handler(handler_t fn) {
    for (int i = 0; valid_handlers[i] != NULL; i++) {
        if (valid_handlers[i] == fn) {
            return true;
        }
    }
    return false;
}

static void demo_fptr_validation(void) {
    printf("\n[3] Function Pointer Validation (software CFI for embedded):\n");

    handler_t legitimate = handler_a;
    handler_t corrupted = (handler_t)(uintptr_t)0xDEADBEEF;

    printf("  Validating handler_a (%p): %s\n",
           (void *)(uintptr_t)legitimate,
           validate_handler(legitimate) ? "VALID" : "INVALID");

    printf("  Validating corrupted (%p): %s\n",
           (void *)(uintptr_t)corrupted,
           validate_handler(corrupted) ? "VALID" : "INVALID");

    /* Safe dispatch */
    if (validate_handler(legitimate)) {
        legitimate();
    }
    if (!validate_handler(corrupted)) {
        printf("  [BLOCKED] Corrupted function pointer rejected.\n");
        printf("  On bare-metal without CFI, calling 0xDEADBEEF would\n");
        printf("  jump to attacker-controlled code (or hard fault).\n");
    }
}

/* ================================================================
 * Pattern 4: Timing-Constant Operations
 *
 * The paper's core attack uses timing side channels (TLB prefetch
 * timing). In embedded systems, timing side channels are used to
 * extract crypto keys (power analysis, EM emanation).
 * Constant-time code is essential for any security-sensitive path.
 * ================================================================ */

/* BAD: timing-dependent comparison (leaks via side channel) */
static bool insecure_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) return false;  /* early exit leaks position */
    }
    return true;
}

/* GOOD: constant-time comparison (no early exit) */
static bool secure_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

static void demo_timing_safe(void) {
    printf("\n[4] Constant-Time Operations (side-channel resistance):\n");

    uint8_t secret[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                           0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    uint8_t guess1[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                           0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    uint8_t guess2[16] = {0xFF, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                           0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    printf("  insecure_compare(secret, correct): %s\n",
           insecure_compare(secret, guess1, 16) ? "match" : "no match");
    printf("  insecure_compare(secret, wrong@0): %s  <-- returns faster!\n",
           insecure_compare(secret, guess2, 16) ? "match" : "no match");

    printf("  secure_compare(secret, correct):   %s\n",
           secure_compare(secret, guess1, 16) ? "match" : "no match");
    printf("  secure_compare(secret, wrong@0):   %s  <-- same time\n",
           secure_compare(secret, guess2, 16) ? "match" : "no match");

    printf("\n  The paper's TLB timing attack has the same principle:\n");
    printf("  memory access patterns that vary based on secret data\n");
    printf("  leak information through timing. Always use constant-time\n");
    printf("  code for security-sensitive comparisons and crypto.\n");
}

int main(void) {
    printf("=== Embedded Hardening Patterns ===\n");
    printf("(Inspired by kernel defenses from the paper)\n\n");

    demo_stack_painting();
    demo_pool_allocator();
    demo_fptr_validation();
    demo_timing_safe();

    printf("\n=== Embedded Hardening Checklist ===\n");
    printf("  [  ] Stack painting + high-water mark monitoring\n");
    printf("  [  ] Pool allocators with canaries and zero-on-free\n");
    printf("  [  ] Function pointer validation before indirect calls\n");
    printf("  [  ] Constant-time comparisons for secrets\n");
    printf("  [  ] MPU regions: code=RX, data=RW, peripherals=RW\n");
    printf("  [  ] -fstack-protector-strong (if supported by target)\n");
    printf("  [  ] -Wstack-usage=N to catch deep stack frames\n");
    printf("  [  ] Disable unused peripherals/DMA channels\n");
    printf("  [  ] Watchdog timer for fault recovery\n");
    printf("  [  ] Secure boot chain (verify firmware signatures)\n");

    return 0;
}
