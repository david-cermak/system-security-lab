#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void win(void)
{
    printf("AUTHENTICATED...\n");
}

static void check_password(const char *pass)
{
    if (strcmp(pass, "mypassword") == 0) {
        win();
        return;
    }
    printf("WRONG PASSWORD\n");
}

struct Frame
{
    char buf[32];
    void (*auth)(const char *);
};

int main(int argc, char **argv)
{
    struct Frame frame;

    frame.auth = check_password;
    printf("win() @ 0x%lx\n", (unsigned long)(uintptr_t)win);

    /* buffer overflow */
    fread(frame.buf, 1, 200, stdin);
    frame.auth(argv[1]);

    return 0;
}
