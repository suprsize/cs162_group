#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/file.h"
#include <stdint.h>


// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

bool is_valid_ptr(void * ptr);
struct file* get_file(int fd);
int read_file(int fd, uint32_t* buffer, size_t count);
int write_file(int fd, uint32_t* buffer, size_t count);


/* Custom filesys functions. */
int add_fd(struct file * file_descriptor);

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */
  int fd_index;               /* Index of newest file descriptor. */
  struct list file_descriptors; /* File descriptor lists */
  struct lock filesys_lock;
  /* James Begin */

  struct list children; /* Keep track of children processes and their respective retvals */
  // struct child_retval child_rv;

  /* James End */

};

void userprog_init(void);


/* Provides an interface for the parent process to keep
 * track of the return status code of the child proc. 
 */
struct child_retval {
  bool has_been_locked; /* used to ensure no other proccess is using it. */
  bool has_been_called;

  int ref_cnt;  /* Determines how many procs are accessing this resource. */
  int retval; /* The return status code. */
  struct semaphore* wait_sema; /* semaphore to wait for return code. */
  struct lock* ref_cnt_lock; /* Lock for ref count. */
};

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

#endif /* userprog/process.h */
