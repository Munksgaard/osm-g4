#include "lock.h"
#include "spinlock.h"
#include "sleepq.h"
#include "interrupt.h"
#include "thread.h"

int lock_reset(lock_t *lock)
{
    sleepq_wake_all(lock);
    spinlock_reset(&lock->slock);
    lock->is_locked = 0;

    return 0; // never fails
}

void lock_acquire(lock_t *lock)
{
    interrupt_status_t intr_status = _interrupt_disable();
    spinlock_acquire(&lock->slock);

    while (lock->is_locked) {
        sleepq_add(lock);
        spinlock_release(&lock->slock);
        thread_switch();
        spinlock_acquire(&lock->slock);
    }

    lock->is_locked = 1;

    spinlock_release(&lock->slock);
    _interrupt_set_state(intr_status);
}

void lock_release(lock_t *lock)
{
    interrupt_status_t intr_status = _interrupt_disable();
    spinlock_acquire(&lock->slock);

    lock->is_locked = 0;
    sleepq_wake(lock);

    spinlock_release(&lock->slock);
    _interrupt_set_state(intr_status);
}
