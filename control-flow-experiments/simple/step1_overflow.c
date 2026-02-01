#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static void safe(const char *cmd)
{
    printf("safe path: %s\n", cmd);
}

static void win(const char *cmd)
{
    system(cmd);
}

struct Frame
{
    char buf[32];
    void (*fn)(const char *);
};

int main(int argc, char **argv)
{
    struct Frame frame;
    const char *cmd = (argc > 1) ? argv[1] : "echo SAFE";

    frame.fn = safe;
    printf("win() @ 0x%lx\n", (unsigned long)(uintptr_t)win);
    fflush(stdout);

    /* Deliberate overflow: reads more than 32 bytes. */
    fread(frame.buf, 1, 200, stdin);
    frame.fn(cmd);

    return 0;
}
