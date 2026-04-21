/*
 * 02_stack_hardening.c - Stack protection mechanisms
 *
 * Paper context: Section 7.3 and Figure 10 show how corrupting saved
 * registers on the kernel stack enables control-flow hijacking. The
 * paper discusses CONFIG_STACKPROTECTOR and CONFIG_RANDOMIZE_KSTACK_OFFSET.
 *
 * These SAME defenses exist for userspace:
 *   -fstack-protector-strong   (stack canaries)
 *   -fcf-protection=full       (CET: shadow stack + indirect branch tracking)
 *   -fstack-clash-protection   (guard pages between stack frames)
 *   -mshstk                    (hardware shadow stack on Intel CET)
 *
 * For embedded: even without an MMU, stack canaries and stack painting
 * (filling stack with known patterns) are critical.
 *
 * Compile (to see the canary in action):
 *   gcc -fstack-protector-strong -o 02_stack_hardening 02_stack_hardening.c
 *
 * Compile WITHOUT protection (to see the overflow succeed silently):
 *   gcc -fno-stack-protector -o 02_stack_noprotect 02_stack_hardening.c
 *
 * Compare assembly to see canary insertion:
 *   gcc -S -fstack-protector-strong -o 02_with_canary.s 02_stack_hardening.c
 *   gcc -S -fno-stack-protector -o 02_no_canary.s 02_stack_hardening.c
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * This is a simplified version of the kernel stack corruption
 * shown in Figure 10 of the paper. In the kernel, the attacker
 * corrupts saved callee-saved registers (rbp-r15) and fn/arg
 * pointers. In userspace, the equivalent is overwriting the
 * saved return address or function pointers on the stack.
 */

typedef void (*callback_fn)(const char *msg);

struct handler {
    char name[16];
    callback_fn on_event;  /* function pointer -- high-value target */
};

static void safe_handler(const char *msg) {
    printf("  [safe_handler] Processing: %s\n", msg);
}

/*
 * Vulnerable function: buffer overflow can overwrite the
 * function pointer, analogous to the kernel register corruption
 * in the paper's exploit (Figure 10, step 4).
 */
static void process_input(struct handler *h, const char *input) {
    char local_buf[16];

    printf("  handler '%s' at %p\n", h->name, (void *)h);
    printf("  callback at %p\n", (void *)(uintptr_t)h->on_event);
    printf("  local_buf at %p (stack)\n", (void *)local_buf);

    /*
     * BUG: No bounds check. If input > 16 bytes, we overflow
     * into adjacent stack data. On a real attack, this would
     * overwrite the return address or saved registers.
     *
     * The stack canary (if enabled) sits between local_buf and
     * the saved frame pointer/return address. Overflow will
     * corrupt the canary and trigger __stack_chk_fail().
     */
    printf("  Copying %zu bytes into 16-byte buffer...\n", strlen(input));
    strcpy(local_buf, input);  /* VULNERABLE: no bounds check */

    printf("  local_buf content: '%.16s...'\n", local_buf);
}

int main(void) {
    printf("=== Stack Hardening Demonstration ===\n\n");

    struct handler h = {
        .name = "event_handler",
        .on_event = safe_handler,
    };

    /* Normal operation */
    printf("[1] Normal call (safe):\n");
    process_input(&h, "hello");
    h.on_event("test event");

    /*
     * Overflow attempt. With -fstack-protector-strong, the
     * canary corruption will be detected and the process aborted.
     * Without it, this silently corrupts the stack.
     *
     * The paper's point: even with protections, side channels
     * can leak stack locations. But the protections still matter
     * because they force attackers into much more complex chains.
     */
    printf("\n[2] Overflow attempt (24 bytes into 16-byte buffer):\n");
    process_input(&h, "AAAAAAAABBBBBBBBCCCCCCCC");

    /* If we get here without canary protection, stack is corrupted */
    printf("\n[3] If you see this, the overflow was NOT detected.\n");
    printf("    Compile with -fstack-protector-strong to catch it.\n");

    return 0;
}
