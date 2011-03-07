/*
 * Userland exec test that doesn't join or halt.
 */

#include "tests/lib.h"

static const char prog[] = "[arkimedes]hello"; /* The program to start. */

int main(void)
{
    int i;
    syscall_exec(prog);
    for (i = 0; i < 100000; i++); /* Wait a bit... */
    return 0;
}
