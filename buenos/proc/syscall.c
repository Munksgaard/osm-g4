/*
 * System calls.
 *
 * Copyright (C) 2003 Juha Aatrokoski, Timo Lilja,
 *   Leena Salmela, Teemu Takanen, Aleksi Virtanen.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: syscall.c,v 1.3 2004/01/13 11:10:05 ttakanen Exp $
 *
 */
#include "kernel/cswitch.h"
#include "proc/syscall.h"
#include "proc/process.h"
#include "kernel/halt.h"
#include "kernel/panic.h"
#include "lib/libc.h"
#include "kernel/assert.h"
#include "drivers/gcd.h"
#include "drivers/device.h"
#include "kernel/interrupt.h"
#include "kernel/lock.h"
#include "kernel/lock_cond.h"
#include "fs/vfs.h"

typedef lock_t usr_lock_t;
typedef cond_t usr_cond_t;

void syscall_exit(int retval)
{
    process_finish(retval);
}

uint32_t syscall_write(uint32_t fd, char* s, int len)
{
    int count;
    gcd_t *gcd;
    if (fd != FILEHANDLE_STDOUT) {
        KERNEL_PANIC("Can only write() to standard output.");
    }
    gcd = process_get_current_process_entry()->fds[1];
    count = gcd->write(gcd, s, len);
    return count;
}

uint32_t syscall_read(uint32_t fd, char* s, int len)
{
    int count = 0;
    gcd_t *gcd;
    if (fd != FILEHANDLE_STDIN) {
        KERNEL_PANIC("Can only read() from standard input.");
    }
    gcd = process_get_current_process_entry()->fds[0];
    count = gcd->read(gcd, s, len);
    return count;
}

uint32_t syscall_join(process_id_t pid)
{
    return process_join(pid);
}

process_id_t syscall_exec(char* filename)
{
    process_id_t child = process_spawn(filename);
    return child;
}

int syscall_fork(void (*func)(int), int arg)
{
    if (process_fork(func, arg) >= 0) {
        return 0;
    } else {
        return -1;
    }
}

int syscall_lock_create(usr_lock_t *usr_lock)
{
    return lock_reset((lock_t*)usr_lock);
}

void syscall_lock_acquire(usr_lock_t *usr_lock)
{
    lock_acquire((lock_t*)usr_lock);
}

void syscall_lock_release(usr_lock_t *usr_lock)
{
    lock_release((lock_t*)usr_lock);
}

int syscall_condition_create(usr_cond_t *cond)
{
    return condition_reset(cond);
}

void syscall_condition_wait(usr_cond_t *cond, usr_lock_t *lock)
{
    condition_wait((cond_t*) cond, (lock_t*) lock);
}

void syscall_condition_signal(usr_cond_t *cond, usr_lock_t *lock)
{
    condition_signal((cond_t*) cond, (lock_t*) lock);
}

void syscall_condition_broadcast(usr_cond_t *cond, usr_lock_t *lock)
{
    condition_broadcast((cond_t*) cond, (lock_t*) lock);
}

openfile_t syscall_open(char *filename)
{
    return vfs_open(filename);
}

int syscall_close(openfile_t file)
{
    return vfs_close(file);
}

int syscall_create(char *pathname, int size)
{
    return vfs_create(pathname, size);
}

int syscall_delete(char *pathname)
{
    return vfs_remove(pathname);
}

void syscall_seek(openfile_t filehandle, int offset)
{
    if (offset < 0) return;
    vfs_seek(filehandle, offset);
}

/**
 * Handle system calls. Interrupts are enabled when this function is
 * called.
 *
 * @param user_context The userland context (CPU registers as they
 * where when system call instruction was called in userland)
 */
void syscall_handle(context_t *user_context)
{
    int retval;

    /* When a syscall is executed in userland, register a0 contains
     * the number of the syscall. Registers a1, a2 and a3 contain the
     * arguments of the syscall. The userland code expects that after
     * returning from the syscall instruction the return value of the
     * syscall is found in register v0. Before entering this function
     * the userland context has been saved to user_context and after
     * returning from this function the userland context will be
     * restored from user_context.
     */
    switch(user_context->cpu_regs[MIPS_REGISTER_A0]) {
    case SYSCALL_HALT:
        halt_kernel();
        break;
    case SYSCALL_EXIT:
        syscall_exit(user_context->cpu_regs[MIPS_REGISTER_A1]);
        break;
    case SYSCALL_WRITE:
        user_context->cpu_regs[MIPS_REGISTER_V0] =
            syscall_write(user_context->cpu_regs[MIPS_REGISTER_A1],
                          (char*)user_context->cpu_regs[MIPS_REGISTER_A2],
                          (user_context->cpu_regs[MIPS_REGISTER_A3]));
        break;
    case SYSCALL_READ:
        user_context->cpu_regs[MIPS_REGISTER_V0] =
            syscall_read(user_context->cpu_regs[MIPS_REGISTER_A1],
                         (char*)user_context->cpu_regs[MIPS_REGISTER_A2],
                         (user_context->cpu_regs[MIPS_REGISTER_A3]));
        break;
    case SYSCALL_JOIN:
        user_context->cpu_regs[MIPS_REGISTER_V0] =
            syscall_join(user_context->cpu_regs[MIPS_REGISTER_A1]);
        break;
    case SYSCALL_EXEC:
        user_context->cpu_regs[MIPS_REGISTER_V0] =
            syscall_exec((char*)user_context->cpu_regs[MIPS_REGISTER_A1]);
        break;
    case SYSCALL_FORK:
        user_context->cpu_regs[MIPS_REGISTER_V0] =
            syscall_fork((void (*)(int))user_context->cpu_regs[MIPS_REGISTER_A1],
                         user_context->cpu_regs[MIPS_REGISTER_A2]);
        break;
    case SYSCALL_LOCK_CREATE:
        user_context->cpu_regs[MIPS_REGISTER_V0] =
            syscall_lock_create((usr_lock_t*)user_context->cpu_regs[MIPS_REGISTER_A1]);
        break;
    case SYSCALL_LOCK_ACQUIRE:
        syscall_lock_acquire((usr_lock_t*)user_context->cpu_regs[MIPS_REGISTER_A1]);
        break;
    case SYSCALL_LOCK_RELEASE:
        syscall_lock_release((usr_lock_t*)user_context->cpu_regs[MIPS_REGISTER_A1]);
        break;
    case SYSCALL_CONDITION_CREATE:
        user_context->cpu_regs[MIPS_REGISTER_V0] =
            syscall_condition_create(
                                     (usr_cond_t*)user_context->cpu_regs[MIPS_REGISTER_A1]);
        break;
    case SYSCALL_CONDITION_WAIT:
        syscall_condition_wait(
                               (usr_cond_t*)user_context->cpu_regs[MIPS_REGISTER_A1],
                               (usr_lock_t*)user_context->cpu_regs[MIPS_REGISTER_A2]);
        break;
    case SYSCALL_CONDITION_SIGNAL:
        syscall_condition_signal(
                                 (usr_cond_t*)user_context->cpu_regs[MIPS_REGISTER_A1],
                                 (usr_lock_t*)user_context->cpu_regs[MIPS_REGISTER_A2]);
        break;
    case SYSCALL_CONDITION_BROADCAST:
        syscall_condition_broadcast(
                                    (usr_cond_t*)user_context->cpu_regs[MIPS_REGISTER_A1],
                                    (usr_lock_t*)user_context->cpu_regs[MIPS_REGISTER_A2]);
        break;
    case SYSCALL_OPEN:
        user_context->cpu_regs[MIPS_REGISTER_V0] =
            syscall_open((char *)user_context->cpu_regs[MIPS_REGISTER_A1]);
        break;
    case SYSCALL_CLOSE:
        user_context->cpu_regs[MIPS_REGISTER_V0] =
            syscall_close((openfile_t)user_context->cpu_regs[MIPS_REGISTER_A1]);
    case SYSCALL_CREATE:
        user_context->cpu_regs[MIPS_REGISTER_V0] =
            syscall_create((char *)user_context->cpu_regs[MIPS_REGISTER_A1],
                           (int)user_context->cpu_regs[MIPS_REGISTER_A2]);
    case SYSCALL_DELETE:
        user_context->cpu_regs[MIPS_REGISTER_V0] =
            syscall_delete((char *)user_context->cpu_regs[MIPS_REGISTER_A1]);
    case SYSCALL_SEEK:
        syscall_seek((openfile_t)user_context->cpu_regs[MIPS_REGISTER_A1],
                     (int)user_context->cpu_regs[MIPS_REGISTER_A2]);
    default:
        KERNEL_PANIC("Unhandled system call\n");
    }

    /* Move to next instruction after system call */
    user_context->pc += 4;
}
