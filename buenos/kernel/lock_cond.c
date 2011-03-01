#include "lock_cond.h"
#include "lock.h"
#include "kernel/sleepq.h"
#include "kernel/thread.h"
#include "kernel/interrupt.h"

int condition_reset(cond_t *cond)
{
    sleepq_wake_all(cond);
    return 0;
}

void condition_wait(cond_t *cond, lock_t *condition_lock)
{
    interrupt_status_t intr_status = _interrupt_disable();
    sleepq_add(cond); // tilføj til q
    _interrupt_set_state(intr_status);
    lock_release(condition_lock); // giv slip på låsen
    thread_switch(); // skift tråd
}

void condition_signal(cond_t *cond, lock_t *condition_lock)
{
    sleepq_wake(cond); // flyt en proces fra q til e
}

void condition_broadcast(cond_t *cond, lock_t *condition_lock)
{
    sleepq_wake_all(cond); // flyt alle processer fra q til e
}
