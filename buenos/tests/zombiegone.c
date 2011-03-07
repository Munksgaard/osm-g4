/*
 * Test automatic removal of zombies.
 */

#include "tests/lib.h"

static const char prog[] = "[arkimedes]badexec"; /* The program to start. */

int main()
{
    while (1) {
        uint32_t child = syscall_exec(prog);
        syscall_join(child);
        printf("Next!\n");
    }
}
