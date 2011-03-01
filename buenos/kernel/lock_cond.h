#ifndef BUENOS_KERNEL_LOCK_COND_H
#define BUENOS_KERNEL_LOCK_COND_H

#include "lock.h"

typedef int* cond_t;

int condition_reset(cond_t *cond);
void condition_wait(cond_t *cond, lock_t *condition_lock);
void condition_signal(cond_t *cond, lock_t *condition_lock);
void condition_broadcast(cond_t *cond, lock_t *condition_lock);

#endif
