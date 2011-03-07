/*
 * Shell!  For running programs!
 */

#include "tests/lib.h"

#define BUFFER_SIZE 100

usr_lock_t output_lock;

uint32_t run(char* cmdline)
{
    return syscall_join(syscall_exec(cmdline));
}

void background_run(char* cmdline)
{
    uint32_t retval = run(cmdline);
    syscall_lock_acquire(&output_lock);
    printf("%s: %d\n", cmdline, retval);
    syscall_lock_release(&output_lock);
    syscall_exit(0);
}

void print_prompt(int last_retval)
{
    syscall_lock_acquire(&output_lock);
    printf("%d> ", last_retval);
    syscall_lock_release(&output_lock);
}

int main(void)
{
    uint32_t child;
    char cmdline[BUFFER_SIZE];
    int count;
    int ret = 0;

    while (1) {
        print_prompt(ret);
        count = readline(cmdline, BUFFER_SIZE);
        if (count == 0) {
            break;
        }
        if (cmdline[count-1] == '&') {
            char* s = malloc(count);
            if (s == NULL) {
                printf("Out of heap memory.\n");
            } else {
                strncpy(s, cmdline, count-1);
                s[count-1] = '\0';
                syscall_fork((void(*)(int))&background_run, (int)s);
            }
        } else {
            child = syscall_exec(cmdline);
            ret = (char)syscall_join(child);
        }
    }
    syscall_halt();
    return 0;
}
