/*
 * 01_uaf_basic.c - Use-After-Free: The fundamental bug class
 *
 * Paper context: The paper assumes a UAF or OOB-write primitive as the
 * starting point for kernel exploitation. UAF is equally devastating in
 * userspace C/C++ code, embedded firmware, and RTOS environments.
 *
 * Key lesson: UAF is not a "kernel problem" -- it's a C/C++ problem.
 * The paper's entire exploit chain starts from this single bug class.
 *
 * Compile:
 *   gcc -O0 -g -fsanitize=address -o 01_uaf_basic 01_uaf_basic.c
 *   gcc -O2 -o 01_uaf_basic_nosanit 01_uaf_basic.c   # dangerous: no detection
 *
 * Hardening flags that catch this:
 *   -fsanitize=address     (ASan - catches UAF at runtime)
 *   -fsanitize=memory      (MSan - catches uninitialized reads)
 *   -fhardened             (GCC 14+ umbrella flag)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct credential {
    int uid;
    int gid;
    char name[32];
    int is_admin;
};

/*
 * This mimics the kernel's cred struct reuse pattern.
 * In the paper (Section 7), the authors reclaim freed slots
 * with attacker-controlled data -- the same principle applies
 * in any allocator that reuses freed memory (glibc malloc,
 * FreeRTOS heap, TLSF, etc.)
 */
int main(void) {
    printf("=== UAF Demonstration (Userspace Analog) ===\n\n");

    /* Step 1: Allocate a "credential" object */
    struct credential *cred = malloc(sizeof(struct credential));
    cred->uid = 1000;
    cred->gid = 1000;
    cred->is_admin = 0;
    strncpy(cred->name, "unprivileged_user", sizeof(cred->name) - 1);
    cred->name[sizeof(cred->name) - 1] = '\0';

    printf("[1] Allocated cred at %p: uid=%d, admin=%d\n",
           (void *)cred, cred->uid, cred->is_admin);

    /* Step 2: Free the credential -- but keep the dangling pointer */
    free(cred);
    printf("[2] Freed cred (pointer still holds %p)\n", (void *)cred);

    /*
     * Step 3: Allocate something of the same size.
     * glibc's malloc will very likely return the SAME address.
     * This is the userspace equivalent of the paper's "in-cache reclaim"
     * technique (Figure 9, step 2).
     */
    char *attacker_data = malloc(sizeof(struct credential));
    memset(attacker_data, 0, sizeof(struct credential));

    /* Simulate attacker-controlled write to reclaimed slot */
    struct credential *fake = (struct credential *)attacker_data;
    fake->uid = 0;         /* root */
    fake->gid = 0;         /* root */
    fake->is_admin = 1;    /* escalated */
    strncpy(fake->name, "pwned_root", sizeof(fake->name) - 1);

    printf("[3] Reclaimed same slot at %p with attacker data\n",
           (void *)attacker_data);

    /*
     * Step 4: Use the dangling pointer -- UAF!
     * The old 'cred' pointer now reads attacker-controlled data.
     * With ASan enabled, this WILL be caught. Without it, silent corruption.
     */
    printf("[4] Reading via dangling pointer:\n");
    printf("    uid=%d, gid=%d, admin=%d, name='%s'\n",
           cred->uid, cred->gid, cred->is_admin, cred->name);

    if (cred->is_admin) {
        printf("\n    [!] PRIVILEGE ESCALATION: dangling pointer sees admin=1\n");
        printf("    This is the userspace analog of kernel UAF exploitation.\n");
    }

    free(attacker_data);
    return 0;
}
