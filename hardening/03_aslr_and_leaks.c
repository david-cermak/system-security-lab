/*
 * 03_aslr_and_leaks.c - Address Space Layout Randomization
 *
 * Paper context: The entire paper is about defeating KASLR (kernel ASLR)
 * by using side channels in defenses. The core lesson for ALL C/C++ devs:
 *
 *   ASLR is not a silver bullet. It is a probabilistic defense that
 *   becomes useless once an address is leaked.
 *
 * Userspace ASLR is enabled by default on Linux, but:
 *   - Format string bugs leak stack/heap addresses
 *   - Info leaks in protocol parsers reveal pointer values
 *   - /proc/self/maps reveals everything (if readable)
 *   - Side channels (timing, cache) can deduce layout
 *
 * For embedded systems without an MMU: there is NO ASLR. Every object
 * is at a fixed, known address. This makes exploitation trivial once
 * you have a single write primitive.
 *
 * Compile as PIE (ASLR-compatible):
 *   gcc -pie -fPIE -o 03_aslr_and_leaks 03_aslr_and_leaks.c
 *
 * Compile as non-PIE (ASLR partially defeated):
 *   gcc -no-pie -o 03_no_aslr 03_aslr_and_leaks.c
 *
 * Run multiple times and compare addresses:
 *   for i in $(seq 1 5); do ./03_aslr_and_leaks 2>/dev/null | head -12; echo "---"; done
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Global data -- lives in .data or .bss segment */
static int global_var = 42;
static char global_buffer[64];

/* Simulates a protocol message with an info leak vulnerability */
struct protocol_msg {
    uint32_t type;
    uint32_t length;
    char payload[64];
    /* BUG: internal pointer leaked to network/log */
    void *internal_ptr;
};

/*
 * Demonstrates how easy it is to leak addresses, defeating ASLR.
 * This is the userspace equivalent of the paper's "location disclosure"
 * concept -- once you know where things are, all randomization is moot.
 */
static void demonstrate_info_leak(void) {
    struct protocol_msg msg;
    msg.type = 1;
    msg.length = sizeof(msg.payload);
    strncpy(msg.payload, "Hello, world!", sizeof(msg.payload) - 1);
    msg.payload[sizeof(msg.payload) - 1] = '\0';

    /* BUG: storing internal pointer in externally-visible struct */
    msg.internal_ptr = &global_var;

    /*
     * If this struct is serialized to a network socket or log,
     * the pointer value leaks the ASLR base of the .data segment.
     * An attacker can then compute the base of every other segment.
     */
    printf("  [INFO LEAK] msg.internal_ptr = %p\n", msg.internal_ptr);
    printf("  An attacker now knows the .data segment base.\n");
    printf("  From here, they can compute .text, .got, .plt offsets.\n");
}

/*
 * Format string vulnerability -- classic ASLR bypass.
 * The paper's TLB side channel is more sophisticated, but the
 * principle is identical: any information about memory layout
 * helps the attacker.
 */
static void format_string_leak(const char *user_input) {
    char buf[128];
    /*
     * BUG: user input used as format string.
     * %p will print stack values, leaking addresses.
     * This is detectable with -Wformat-security (enabled by -Wall).
     */
    snprintf(buf, sizeof(buf), user_input);
    printf("  [FORMAT STRING] Output: %s\n", buf);
}

int main(void) {
    printf("=== ASLR and Information Leaks ===\n\n");

    /* Show current memory layout */
    int stack_var = 0;
    void *heap_ptr = malloc(64);

    printf("[1] Memory layout (run multiple times to see randomization):\n");
    printf("  .text  (main)       = %p\n", (void *)(uintptr_t)main);
    printf("  .data  (global_var) = %p\n", (void *)&global_var);
    printf("  .bss   (global_buf) = %p\n", (void *)global_buffer);
    printf("  stack  (stack_var)  = %p\n", (void *)&stack_var);
    printf("  heap   (malloc'd)   = %p\n", heap_ptr);

    printf("\n[2] Information leak via struct pointer:\n");
    demonstrate_info_leak();

    printf("\n[3] Format string leak (prints stack values):\n");
    format_string_leak("%p %p %p %p");

    printf("\n[4] Key takeaways for non-kernel developers:\n");
    printf("  - PIE+ASLR randomizes all segments, but one leak breaks it all\n");
    printf("  - Embedded systems without MMU have NO ASLR at all\n");
    printf("  - Never expose pointer values in logs, error messages, or wire formats\n");
    printf("  - Use -Wformat-security -Wformat=2 to catch format string bugs\n");
    printf("  - The paper shows even KERNEL ASLR falls to side channels --\n");
    printf("    userspace ASLR is no stronger\n");

    free(heap_ptr);
    return 0;
}
