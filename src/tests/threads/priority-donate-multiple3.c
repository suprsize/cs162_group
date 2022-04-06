/* The main thread acquires a lock, then it creates three higher-priority
   threads. Each of these threads blocks attempts to acquire the lock
   and thus donate their priority to the main thread. Each thread will
   print an output that should follow the strict priority scheduler with
   priority donation. 
   Based on a test originally submitted for Stanford's CS 140 in Winter 1999
   Modified by Brian Faun <brianfaun@berkeley.edu. */

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/thread.h"

static thread_func a_thread_func;
static thread_func b_thread_func;

void test_priority_donate_multiple3(void) {
    struct lock a;
    struct semaphore b;

    /* This test does not work with the MLFQS. */
    ASSERT(active_sched_policy == SCHED_PRIO);

    /* Make sure our priority is the default. */
    ASSERT(thread_get_priority() == PRI_DEFAULT);

    lock_init(&a);
    sema_init(b, 1);
    sema_down(b);

    thread_create("thread 1", PRI_DEFAULT + 1, one_thread_func, &a);
    msg("First thread should have priority %d.  Actual priority: %d.", PRI_DEFAULT + 1,
        thread_get_priority());

    thread_create("thread 2", PRI_DEFAULT + 2, two_thread_func, &b);
    msg("Second thread should have priority %d.  Actual priority: %d.", PRI_DEFAULT + 2,
        thread_get_priority());

    thread_create("thread 3", PRI_DEFAULT + 3, three_thread_func, &b);
    msg("Third thread should have priority %d.  Actual priority: %d.", PRI_DEFAULT + 3,
        thread_get_priority());

    sema_up(b);
    printf("Fourth print.");
    msg("Threads one, three, two should have just finished, in that order.");
}
static void one_thread_func(void* lock_, void* sema_) {
    struct lock* lock = lock_;
    struct semaphore* sema = sema_;

    lock_acquire(lock);
    msg("Thread one acquired lock a.");
    sema_down(sema);
    printf("First print.")
    lock_release(lock);
    msg("Thread one finished.");
}

static void two_thread_func(void* lock_, void* sema_) {
    struct lock* lock = lock_;
    struct semaphore* sema = sema_;
    sema_down(sema);
    msg("Thread two sema down on semaphore b.");
    printf("Third print.");
    msg("Thread two finished.");
}

static void three_thread_func(void* lock_, void* sema_) {
    struct lock* lock = lock_;
    struct semaphore* sema = sema_;
    lock_acquire(lock);
    msg("Thread three acquired lock a.");
    printf("Second print.");
    msg("Thread three finished.");
}
