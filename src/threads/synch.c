/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include "list.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* Lock manager for when user is allocated. */
typedef struct user_lock {
  struct lock* kernel_lock;
  struct thread* holder;
  struct thread* next_holder;
  struct list wait_queue;
  struct list_elem elem;
  char* user_ptr;
} user_lock;

/* Semaphore manager for when user is allocated. */
typedef struct user_semaphore {
	struct semaphore* kernel_semaphore;
	char* usr_ptr;	
	struct thread* holder;	
  struct thread* next_holder;
  struct list wait_queue;
  struct list_elem elem;
} user_semaphore;

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
     decrement it.

   - up or "V": increment the value (and wake up one waiting
     thread, if any). */
void sema_init(struct semaphore* sema, unsigned value) {
  ASSERT(sema != NULL);

  sema->value = value;
  list_init(&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. */
void sema_down(struct semaphore* sema) {
  enum intr_level old_level;

  ASSERT(sema != NULL);
  ASSERT(!intr_context());

  old_level = intr_disable();
  while (sema->value == 0) {
    list_push_back(&sema->waiters, &thread_current()->elem);
    thread_block();
  }
  sema->value--;
  intr_set_level(old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool sema_try_down(struct semaphore* sema) {
  enum intr_level old_level;
  bool success;

  ASSERT(sema != NULL);

  old_level = intr_disable();
  if (sema->value > 0) {
    sema->value--;
    success = true;
  } else
    success = false;
  intr_set_level(old_level);

  return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void sema_up(struct semaphore* sema) {
  enum intr_level old_level;
  struct thread *t;
  bool preempt = false;

  ASSERT(sema != NULL);

  old_level = intr_disable();
  if (!list_empty(&sema->waiters)) {
    t = next_schedule_prio(&sema->waiters);
    list_remove(&t->elem);
    thread_unblock(t);
    preempt = t->e_priority > thread_get_priority();
  } else {
    t = NULL;
  }
  sema->value++;

  if (preempt && intr_context()) {
    intr_yield_on_return();
    intr_set_level(old_level);
  } else if (preempt && !intr_context()){
    intr_set_level(old_level);
    thread_yield();
  } else {
    intr_set_level(old_level);
  }

}

static void sema_test_helper(void* sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void sema_self_test(void) {
  struct semaphore sema[2];
  int i;

  printf("Testing semaphores...");
  sema_init(&sema[0], 0);
  sema_init(&sema[1], 0);
  thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
  for (i = 0; i < 10; i++) {
    sema_up(&sema[0]);
    sema_down(&sema[1]);
  }
  printf("done.\n");
}

/* Thread function used by sema_self_test(). */
static void sema_test_helper(void* sema_) {
  struct semaphore* sema = sema_;
  int i;

  for (i = 0; i < 10; i++) {
    sema_down(&sema[0]);
    sema_up(&sema[1]);
  }
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void lock_init(struct lock* lock) {
  ASSERT(lock != NULL);

  lock->holder = NULL;
  sema_init(&lock->semaphore, 1);
}

bool user_lock_init(struct lock* lock) {
  user_lock *userlock = malloc(sizeof(user_lock));
  user_semaphore *usersemaphore = malloc(sizeof(user_semaphore));
  if (userlock == NULL || usersemaphore == NULL) {
    return false;
  }
  return true;
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. 
   Acquires lock for user thread and includes lock priority donation. */
void lock_acquire (struct lock* lock) {
  
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(!lock_held_by_current_thread(lock));

  enum intr_level old_level;

  struct thread *current_thread = thread_current();

  // old_level = intr_disable(); ?

  if (lock->holder != NULL) {
    current_thread->waiting_on = lock;

    struct lock *lock_ptr = lock;
    struct thread *lock_holder;

    while (lock_ptr) {
      lock_holder = lock_ptr->holder;

      // Might be redundant to check.. since current thread should already be the highest,
      // .. but maybe there is a sleeping thread that has higher priority that is also 
      // holding our lock

      if (lock_holder->e_priority < current_thread->e_priority) {
        lock_holder->e_priority = current_thread->e_priority;
        lock_ptr = lock_holder->waiting_on;
        continue;
      } break;
    }
  }

  // intr_set_level(old_level); ?

  sema_down(&lock->semaphore);

  
  old_level = intr_disable();

  current_thread->waiting_on = NULL;
  lock->holder = current_thread;

  intr_set_level(old_level);
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool lock_try_acquire(struct lock* lock) {
  bool success;

  ASSERT(lock != NULL);
  ASSERT(!lock_held_by_current_thread(lock));

  success = sema_try_down(&lock->semaphore);
  if (success)
    lock->holder = thread_current();
  return success;
}

/* Releases LOCK, which must be owned by the current thread.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler.

   Releases the lock for user threads and includes priority donation. 
   Should reset a thread's priority that held the lock back to the 
   maximum of base priority or other donations. */
void lock_release(struct lock* lock) {
  ASSERT(lock != NULL);
  ASSERT(lock_held_by_current_thread(lock));

  struct thread *t = thread_current();

  enum intr_level old_level;
  old_level = intr_disable();

  for (struct list_elem *e = list_begin(&t->locks); e != list_end(&t->locks); e = list_next(e)) {
    if (lock == list_entry(e, struct lock, elem)) {
      list_remove(e);
    }
  }

  lock->holder = NULL;
  sema_up(&lock->semaphore);

  intr_set_level(old_level);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool lock_held_by_current_thread(const struct lock* lock) {
  ASSERT(lock != NULL);

  return lock->holder == thread_current();
}

/* Initializes a readers-writers lock */
void rw_lock_init(struct rw_lock* rw_lock) {
  lock_init(&rw_lock->lock);
  cond_init(&rw_lock->read);
  cond_init(&rw_lock->write);
  rw_lock->AR = rw_lock->WR = rw_lock->AW = rw_lock->WW = 0;
}

/* Acquire a writer-centric readers-writers lock */
void rw_lock_acquire(struct rw_lock* rw_lock, bool reader) {
  // Must hold the guard lock the entire time
  lock_acquire(&rw_lock->lock);

  if (reader) {
    // Reader code: Block while there are waiting or active writers
    while ((rw_lock->AW + rw_lock->WW) > 0) {
      rw_lock->WR++;
      cond_wait(&rw_lock->read, &rw_lock->lock);
      rw_lock->WR--;
    }
    rw_lock->AR++;
  } else {
    // Writer code: Block while there are any active readers/writers in the system
    while ((rw_lock->AR + rw_lock->AW) > 0) {
      rw_lock->WW++;
      cond_wait(&rw_lock->write, &rw_lock->lock);
      rw_lock->WW--;
    }
    rw_lock->AW++;
  }

  // Release guard lock
  lock_release(&rw_lock->lock);
}

/* Release a writer-centric readers-writers lock */
void rw_lock_release(struct rw_lock* rw_lock, bool reader) {
  // Must hold the guard lock the entire time
  lock_acquire(&rw_lock->lock);

  if (reader) {
    // Reader code: Wake any waiting writers if we are the last reader
    rw_lock->AR--;
    if (rw_lock->AR == 0 && rw_lock->WW > 0)
      cond_signal(&rw_lock->write, &rw_lock->lock);
  } else {
    // Writer code: First try to wake a waiting writer, otherwise all waiting readers
    rw_lock->AW--;
    if (rw_lock->WW > 0)
      cond_signal(&rw_lock->write, &rw_lock->lock);
    else if (rw_lock->WR > 0)
      cond_broadcast(&rw_lock->read, &rw_lock->lock);
  }

  // Release guard lock
  lock_release(&rw_lock->lock);
}

/* One semaphore in a list. */
struct semaphore_elem {
  struct list_elem elem;      /* List element. */
  struct semaphore semaphore; /* This semaphore. */
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void cond_init(struct condition* cond) {
  ASSERT(cond != NULL);

  list_init(&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void cond_wait(struct condition* cond, struct lock* lock) {
  struct semaphore_elem waiter;

  ASSERT(cond != NULL);
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(lock_held_by_current_thread(lock));

  sema_init(&waiter.semaphore, 0);
  list_push_back(&cond->waiters, &waiter.elem);
  lock_release(lock);
  sema_down(&waiter.semaphore);
  lock_acquire(lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_signal(struct condition* cond, struct lock* lock UNUSED) {
  ASSERT(cond != NULL);
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(lock_held_by_current_thread(lock));

  if (!list_empty(&cond->waiters)) {
    struct list_elem *e;
    int highest_priority = -1;

    struct semaphore* wakeup_s;
    struct semaphore_elem* wakeup_se;

    for (e = list_begin(&cond->waiters); e != list_end(&cond->waiters);
        e = list_next(e)) {
      struct semaphore_elem* se = list_entry(e, struct semaphore_elem, elem);
      struct semaphore* s = &se->semaphore;
      struct thread* t = next_schedule_prio(&s->waiters);
      if (t->e_priority > highest_priority) {
        wakeup_s = s;
        wakeup_se = se;
        highest_priority = t->e_priority;
      }
    }
    list_remove(&wakeup_se->elem);
    sema_up(wakeup_s);
    //sema_up(&list_entry(list_pop_front(&cond->waiters), struct semaphore_elem, elem)->semaphore);
  }
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_broadcast(struct condition* cond, struct lock* lock) {
  ASSERT(cond != NULL);
  ASSERT(lock != NULL);

  while (!list_empty(&cond->waiters))
    cond_signal(cond, lock);
}
