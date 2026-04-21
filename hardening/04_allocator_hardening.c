/*
 * 04_allocator_hardening.c - Heap allocator security
 *
 * Paper context: The paper heavily relies on "allocator massaging"
 * (heap feng shui) to place objects at predictable locations within
 * kernel slab caches. The kernel has defenses like:
 *   CONFIG_SLAB_FREELIST_HARDENED  (protects freelist metadata)
 *   CONFIG_SLAB_FREELIST_RANDOM    (randomizes allocation order)
 *   CONFIG_INIT_ON_FREE_DEFAULT_ON (zeroes freed memory)
 *
 * These concepts apply DIRECTLY to userspace and embedded:
 *   - glibc malloc has inline metadata (fd/bk pointers) that can be corrupted
 *   - Embedded allocators (FreeRTOS heap_4, TLSF) often have NO hardening
 *   - Zeroing on free prevents information leaks from recycled buffers
 *
 * Compile:
 *   gcc -O2 -o 04_allocator_hardening 04_allocator_hardening.c
 *
 * Hardening options for userspace allocators:
 *   - Use hardened allocators: jemalloc, mimalloc, scudo (LLVM)
 *   - Link with scudo: clang -fsanitize=scudo
 *   - Environment: MALLOC_PERTURB_=0xAA (glibc: fill freed memory)
 *   - explicit_bzero() / memset_s() before free for sensitive data
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Simulates a sensitive object (like kernel's cred struct) */
struct session_token {
    uint64_t token_id;
    char secret_key[32];
    int privilege_level;
};

/*
 * Demonstrates that freed memory retains its contents.
 * This is the userspace version of why the kernel needs
 * CONFIG_INIT_ON_FREE_DEFAULT_ON.
 */
static void demo_stale_data_leak(void) {
    printf("[1] Stale data after free (information leak):\n");

    struct session_token *token = malloc(sizeof(*token));
    token->token_id = 0xDEADBEEF;
    memcpy(token->secret_key, "super_secret_key_12345678!!!\0\0\0\0", 32);
    token->privilege_level = 99;

    printf("  Allocated token at %p, secret='%.32s'\n",
           (void *)token, token->secret_key);

    /* Free WITHOUT clearing -- data persists in heap */
    void *old_addr = token;
    free(token);

    /* Reallocate same size -- likely gets same address */
    char *leaked = malloc(sizeof(struct session_token));
    printf("  Reallocated at %p (same? %s)\n",
           (void *)leaked, leaked == old_addr ? "YES" : "no");

    if (leaked == old_addr) {
        struct session_token *ghost = (struct session_token *)leaked;
        printf("  Leaked secret from freed memory: '%.32s'\n",
               ghost->secret_key);
        printf("  Leaked privilege_level: %d\n", ghost->privilege_level);
        printf("\n  FIX: Use explicit_bzero() before free().\n");
    }
    free(leaked);
}

/*
 * Demonstrates safe deallocation pattern.
 * This is what CONFIG_INIT_ON_FREE_DEFAULT_ON does for the kernel.
 */
static void demo_safe_free(void) {
    printf("\n[2] Safe free with explicit_bzero():\n");

    struct session_token *token = malloc(sizeof(*token));
    token->token_id = 0xCAFEBABE;
    memcpy(token->secret_key, "another_secret_key_9876543!!\0\0\0\0", 32);
    token->privilege_level = 42;

    printf("  Token at %p, secret='%.32s'\n",
           (void *)token, token->secret_key);

    void *old_addr = token;

    /* SAFE: Clear before free */
    explicit_bzero(token, sizeof(*token));
    free(token);

    /* Reallocate and check */
    char *check = malloc(sizeof(struct session_token));
    if (check == old_addr) {
        struct session_token *ghost = (struct session_token *)check;
        printf("  After explicit_bzero + free, secret='%.32s'\n",
               ghost->secret_key);
        printf("  privilege_level=%d (should be 0)\n",
               ghost->privilege_level);
    }
    free(check);
}

/*
 * Demonstrates heap metadata corruption.
 * In the paper, corrupting slab freelist pointers is a key step.
 * glibc's malloc uses inline fd/bk pointers that are equally vulnerable.
 *
 * CONFIG_SLAB_FREELIST_HARDENED XORs freelist pointers with a random
 * cookie. glibc does something similar (safe-linking since 2.32).
 */
static void demo_heap_layout(void) {
    printf("\n[3] Heap allocation patterns (allocator massaging):\n");
    printf("  The paper uses 'massaging' to control object placement.\n");
    printf("  The same works with glibc malloc:\n\n");

    /* Allocate several same-sized objects */
    void *ptrs[8];
    for (int i = 0; i < 8; i++) {
        ptrs[i] = malloc(64);
        printf("  alloc[%d] = %p", i, ptrs[i]);
        if (i > 0) {
            printf("  (delta from prev: %+ld bytes)",
                   (long)((char *)ptrs[i] - (char *)ptrs[i-1]));
        }
        printf("\n");
    }

    /* Free every other one to create holes */
    printf("\n  Freeing [1], [3], [5], [7] to create holes...\n");
    for (int i = 1; i < 8; i += 2) {
        free(ptrs[i]);
        ptrs[i] = NULL;
    }

    /* New allocations fill the holes (LIFO in glibc fastbins) */
    printf("  Allocating 4 new same-sized objects:\n");
    for (int i = 0; i < 4; i++) {
        void *p = malloc(64);
        printf("  new[%d] = %p\n", i, p);
        free(p);
    }

    for (int i = 0; i < 8; i++) {
        if (ptrs[i]) free(ptrs[i]);
    }

    printf("\n  Takeaway: malloc reuse is predictable. An attacker who\n");
    printf("  controls allocation/deallocation order can place objects\n");
    printf("  at known heap offsets -- just like kernel slab massaging.\n");
}

int main(void) {
    printf("=== Allocator Hardening (Userspace Analog) ===\n\n");
    demo_stale_data_leak();
    demo_safe_free();
    demo_heap_layout();

    printf("\n[4] Hardening recommendations:\n");
    printf("  - explicit_bzero() sensitive data before free()\n");
    printf("  - Use hardened allocators (scudo, mimalloc, jemalloc)\n");
    printf("  - MALLOC_PERTURB_ environment variable for testing\n");
    printf("  - Embedded: add canaries/cookies to your custom allocator\n");
    printf("  - Embedded: consider zeroing all freed blocks by default\n");
    printf("  - Pool allocators with fixed-size objects limit cross-type confusion\n");

    return 0;
}
