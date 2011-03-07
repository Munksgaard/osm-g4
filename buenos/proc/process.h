/*
 * Process startup.
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
 * $Id: process.h,v 1.4 2003/05/16 10:13:55 ttakanen Exp $
 *
 */

#ifndef BUENOS_PROC_PROCESS
#define BUENOS_PROC_PROCESS

#include "lib/types.h"
#include "kernel/config.h"
#include "drivers/gcd.h"

#define USERLAND_STACK_TOP 0x7fffeffc

#define USERLAND_STACK_MASK (PAGE_SIZE_MASK*CONFIG_USERLAND_STACK_SIZE)

#define MAX_PROCESSES 8

#define PROCESS_NAME_MAX 128

#define MAX_OPEN_FILES 2

typedef int process_id_t;

typedef enum {
    PROCESS_FREE,
    PROCESS_RUNNING,
    PROCESS_ZOMBIE
} process_state_t;
 
/* process table data structure */
typedef struct {
    char executable[PROCESS_NAME_MAX];
    process_state_t state;
    int retval; /* Return value - negative if we have been joined. */
    gcd_t* fds[MAX_OPEN_FILES]; /* File descriptors - kinda - insufficient when
                                   real filesystem support is added. */
    process_id_t parent; /* Parent, negative if none. */
    process_id_t first_zombie; /* PID of first nonjoined dead child. */
    process_id_t prev_zombie; /* PID of previous zombie sibling. */
    process_id_t next_zombie; /* PID of next zombie sibling. */
    int children; /* Number of nonjoined child processes. */
    int threads; /* Number of threads in the process. */
    uint32_t stack_end; /* End of lowest stack. */
    uint32_t bot_free_stack; /* Start of lowest free stack (0 if
                                none). */
} process_table_t;

void process_init(void);

process_id_t process_spawn(const char *executable);

process_id_t process_get_current_process(void);
process_table_t *process_get_current_process_entry(void);

void process_finish(int retval);

uint32_t process_join(process_id_t pid);

int process_fork(void (*func)(int), int arg);

#endif
