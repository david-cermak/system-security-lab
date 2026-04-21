/*
 * 05_compiler_flags_demo.c - Comprehensive compiler hardening flags
 *
 * Paper context: The kernel uses defenses like CONFIG_ZERO_CALL_USED_REGS,
 * CONFIG_STACKPROTECTOR, strict RWX permissions, and CFI. ALL of these
 * have userspace equivalents via compiler flags.
 *
 * This file is designed to be compiled with various flag combinations
 * to demonstrate what each defense catches or prevents.
 *
 * === COMPILATION MATRIX ===
 *
 * Minimal (DANGEROUS -- typical embedded "just make it work" build):
 *   gcc -O2 -o 05_minimal 05_compiler_flags_demo.c
 *
 * Warnings only (catches bugs at compile time):
 *   gcc -O2 -Wall -Wextra -Werror -Wformat=2 -Wconversion \
 *       -Wshadow -Wdouble-promotion -o 05_warnings 05_compiler_flags_demo.c
 *
 * Hardened userspace (production):
 *   gcc -O2 -Wall -Wextra \
 *       -fstack-protector-strong \
 *       -fstack-clash-protection \
 *       -fcf-protection=full \
 *       -D_FORTIFY_SOURCE=3 \
 *       -D_GLIBCX_ASSERTIONS \
 *       -pie -fPIE \
 *       -Wl,-z,relro,-z,now \
 *       -Wl,-z,noexecstack \
 *       -o 05_hardened 05_compiler_flags_demo.c
 *
 * Full sanitizer build (development/CI):
 *   gcc -O1 -g -fno-omit-frame-pointer \
 *       -fsanitize=address,undefined \
 *       -o 05_sanitized 05_compiler_flags_demo.c
 *
 * Clang with extra hardening:
 *   clang -O2 -Wall -Wextra \
 *       -fstack-protector-strong \
 *       -fcf-protection=full \
 *       -fsanitize=safe-stack \
 *       -D_FORTIFY_SOURCE=3 \
 *       -pie -fPIE \
 *       -Wl,-z,relro,-z,now \
 *       -o 05_clang_hardened 05_compiler_flags_demo.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
 * _FORTIFY_SOURCE replaces common string/memory functions with
 * bounds-checked versions. It catches buffer overflows at runtime
 * that the compiler can prove exceed the destination size.
 *
 * Kernel equivalent: Various CONFIG_FORTIFY_SOURCE checks in the
 * kernel's memcpy/strcpy implementations.
 */
static void demo_fortify_source(void) {
    printf("[1] _FORTIFY_SOURCE demonstration:\n");

    char dest[8];
    const char *safe_src = "hello";
    const char *dangerous_src = "this_string_is_way_too_long_for_dest";

    /* Safe copy -- always works */
    strncpy(dest, safe_src, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\0';
    printf("  Safe copy: '%s'\n", dest);

    /*
     * With _FORTIFY_SOURCE=2 or =3, this memcpy is replaced with
     * __memcpy_chk() which verifies the copy size against the
     * compile-time known buffer size. If it overflows, the program
     * is aborted with a clear error message.
     *
     * Without _FORTIFY_SOURCE, this silently corrupts the stack.
     *
     * Uncomment to trigger:
     * memcpy(dest, dangerous_src, strlen(dangerous_src));
     */
    printf("  (overflow test commented out -- uncomment to trigger)\n");
    (void)dangerous_src;
}

/*
 * -fstack-protector-strong inserts canaries for functions that have:
 *   - Local arrays
 *   - Address-taken local variables
 *   - alloca() calls
 *
 * Kernel equivalent: CONFIG_STACKPROTECTOR_STRONG
 */
static void demo_stack_protector(int should_overflow) {
    printf("\n[2] Stack protector (canary) demonstration:\n");
    char buffer[32];

    if (should_overflow) {
        /*
         * This overflow will corrupt the stack canary.
         * With -fstack-protector-strong: DETECTED, process killed.
         * Without: silent corruption, potential code execution.
         */
        memset(buffer, 'A', 64);  /* 64 > 32 = overflow */
        printf("  Overflow completed (canary should catch this)\n");
    } else {
        memset(buffer, 'B', 31);
        buffer[31] = '\0';
        printf("  Safe fill: '%s'\n", buffer);
    }
}

/*
 * -Wl,-z,relro,-z,now makes the GOT (Global Offset Table) read-only
 * after program startup. Without this, an attacker who can write to
 * the GOT can redirect any library function call.
 *
 * Kernel equivalent: CONFIG_STRICT_*_RWX (no writable+executable memory)
 */
static void demo_relro_concept(void) {
    printf("\n[3] RELRO concept (GOT protection):\n");
    printf("  printf is at: %p\n", (void *)(uintptr_t)printf);
    printf("  malloc is at: %p\n", (void *)(uintptr_t)malloc);
    printf("  With full RELRO (-Wl,-z,relro,-z,now), the GOT is\n");
    printf("  mapped read-only after startup. An attacker cannot\n");
    printf("  overwrite these entries to redirect function calls.\n");
    printf("  Without RELRO, overwriting printf's GOT entry with\n");
    printf("  system() gives instant code execution.\n");
}

/*
 * -fcf-protection=full enables Intel CET (Control-flow Enforcement):
 *   - Shadow stack: hardware-protected return address backup
 *   - IBT: indirect branch tracking (ENDBR64 instructions)
 *
 * Kernel equivalent: CONFIG_X86_KERNEL_IBT
 *
 * For embedded ARM: -mbranch-protection=standard (PAC+BTI)
 */
static void demo_cfi_concept(void) {
    printf("\n[4] Control-Flow Integrity concept:\n");

    typedef int (*operation_fn)(int, int);

    /* Legitimate function pointer usage */
    operation_fn op = NULL;
    int a = 10, b = 3;

    /* Simulate function pointer table (like a vtable) */
    printf("  Function pointer 'op' at %p\n", (void *)&op);
    printf("  With CFI (-fcf-protection=full), indirect calls\n");
    printf("  must land on valid function entries (ENDBR64).\n");
    printf("  Corrupting 'op' to point to a ROP gadget would\n");
    printf("  trigger a #CP exception on CET-capable hardware.\n");

    (void)op;
    (void)a;
    (void)b;
}

/*
 * -fzero-call-used-regs=used-gpr
 * Zeroes registers used by a function before return, preventing
 * information leaks through register contents.
 *
 * Kernel equivalent: CONFIG_ZERO_CALL_USED_REGS
 */
static int sensitive_computation(int secret) {
    /* After this function returns, registers used for 'secret'
     * and intermediate values will be zeroed (with the flag enabled).
     * Without it, the secret may remain in registers for a
     * speculative execution attack or register-based info leak. */
    return secret * 31337 + 42;
}

int main(int argc, char *argv[]) {
    printf("=== Compiler Hardening Flags Demonstration ===\n\n");

    demo_fortify_source();
    demo_stack_protector(0); /* pass 1 to trigger overflow */
    demo_relro_concept();
    demo_cfi_concept();

    int result = sensitive_computation(12345);
    printf("\n[5] Register zeroing (-fzero-call-used-regs):\n");
    printf("  Result: %d\n", result);
    printf("  With -fzero-call-used-regs=used-gpr, the registers\n");
    printf("  used for the secret computation are zeroed on return.\n");

    printf("\n=== Summary of Compiler Hardening Flags ===\n");
    printf("  Flag                          | Kernel Equivalent\n");
    printf("  ------------------------------|-----------------------------------\n");
    printf("  -fstack-protector-strong      | CONFIG_STACKPROTECTOR_STRONG\n");
    printf("  -fstack-clash-protection      | CONFIG_VMAP_STACK (guard pages)\n");
    printf("  -fcf-protection=full          | CONFIG_X86_KERNEL_IBT\n");
    printf("  -D_FORTIFY_SOURCE=3           | CONFIG_FORTIFY_SOURCE\n");
    printf("  -fzero-call-used-regs         | CONFIG_ZERO_CALL_USED_REGS\n");
    printf("  -pie -fPIE                    | KASLR\n");
    printf("  -Wl,-z,relro,-z,now           | CONFIG_STRICT_*_RWX\n");
    printf("  -Wl,-z,noexecstack            | NX/W^X enforcement\n");
    printf("  -fsanitize=address            | KASAN\n");
    printf("  -fsanitize=undefined           | KUBSAN\n");
    printf("  -fsanitize=cfi (clang)        | CONFIG_CFI_CLANG\n");

    (void)argc;
    (void)argv;
    return 0;
}
