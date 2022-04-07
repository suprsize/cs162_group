
#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <float.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/exception.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/input.h"

/* A list of all processes */
struct list pcb_list;
struct lock pcb_list_lock;

struct myFile {
  struct file* file_ptr;
  struct list_elem elem;
};

struct start_pthread_args {
  struct semaphore stack_ready;
  stub_fun sf;
  pthread_fun tf;
  struct process* daddy;
  bool error;
  void* aux;
};

static struct semaphore temporary;
static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp);
bool setup_thread(void (**eip)(void), void** esp, void* arg, pthread_fun tf);

/* Generates a retval struct so procs can read/write exit
 * codes in a synchronized manner.*/
struct retval* generate_retval() {
  struct retval* _retval;

  _retval = malloc(sizeof(struct retval));

  if (_retval == NULL) {
    return NULL;
  }

  _retval->value = -1;
  _retval->load_success = -1;
  _retval->tid = thread_current()->tid;

  // the parent references this in the children list.
  // the child references this in the PCb. 
  // If this is the main proc (first process), change this to 1.
  _retval->ref_cnt = 2;

  sema_init(&(_retval->wait_sema), 0);
  sema_init(&(_retval->wait_load), 0);
  lock_init(&(_retval->ref_cnt_lock));

  return _retval;
}

/* Populates a given process control block with 
 * the default values. Returns true on a success. */
bool populate_pcb(struct process* pcb) {
  struct thread* t;

  if (pcb == NULL) {
    return false;
  }

  t = thread_current();

  pcb->pagedir = NULL;

  pcb->main_thread = t;

  pcb->exit = false;

  // initialize the pointer to PHYS_BASE and this will change in setup_thread
  pcb->last_stack_address = ((uint8_t *) PHYS_BASE) - PGSIZE;

  // initialize the file descriptor table
  list_init(&(t->pcb->file_descriptors));

  // initialize the global lock of filesys calls
  lock_init(&t->pcb->filesys_lock);
  // initialize the exit lock of the pcb exit status for multithreading
  lock_init(&t->pcb->exit_lock);
  // initialize the user lock list for the process
  list_init(&t->pcb->lock_list);
  // initialize the user semaphore list for the process
  list_init(&t->pcb->sema_list);

  /* fd codes 0 to 2 are reserved. */
  pcb->fd_index = 2;

  // TODO free everything below on exit.

  /* generate a pointer to the PCB's retval struct. */
  pcb->retval = generate_retval();

  /* copies thread name to process name and ensures a NULL terminator. */
  strlcpy(t->pcb->process_name, t->name, sizeof t->name);
  *(t->pcb->process_name + sizeof(t->name)) = NULL;

  /* Initializes the list of file descriptors and children retvals. */
  list_init(&(pcb->file_descriptors));
  list_init(&(pcb->children));
  list_init(&(pcb->threads_retvals));

  /* Initialize and add in the thread retval. */
  struct thread_retval* new_thread_retval = malloc(sizeof(struct thread_retval));
  new_thread_retval->tid = thread_current()->tid;
  new_thread_retval->is_terminated = false;
  new_thread_retval->is_exited = false;
  lock_init(&new_thread_retval->join_lock);
  sema_init(&new_thread_retval->join_sema, 0);
  t->retval = new_thread_retval;
  list_push_back(&pcb->threads_retvals, &new_thread_retval->elem);

  return true;
}

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Initialize the process list and its lock. */
  lock_init(&(pcb_list_lock));
  list_init(&(pcb_list));

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = populate_pcb(t->pcb);

  /* Kill the kernel if we did not succeed */
  ASSERT(success);

  /* Add this PCB to the global PCB list */
  lock_acquire(&(pcb_list_lock));
  list_push_back(&(pcb_list), &(t->pcb->elem));
  lock_release(&(pcb_list_lock));

  /* There is no parent of the init process. Retval of this is only referneced by me. */
  t->pcb->retval->ref_cnt = 1;
}


/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  char* fn_copy;
  tid_t tid;
  struct thread* child_thread;
  struct process* child_pcb;
  struct process* current_pcb;
  struct retval* child_retval;



  current_pcb = thread_current()->pcb;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0); //TODO NEED TO CHANGE IT TO MALLOC
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page(fn_copy);

  /** 
   * TODO erase this for project submission
   * Explanation on wtf is going on down below
   *
   * We need to wait for child to initialize the PCB. We wait
   * by using the semaphore child_thread->pcb_ready.
   *
   * Once the PCB is initialized, we access the child's retval struct
   * for two reasons:
   *
   * 1) Wait for the status of the load() function in start_process.
   * 2) Add the child retval struct to the parent's children list.
   */

  child_thread = thread_get(tid);

  /* Wait until child has created the PCB with its
   * retval struct. */
  sema_down(&(child_thread->pcb_ready));
  child_pcb = child_thread->pcb;

  // Neccesary.
  // there is a chance that PCB allocation fails.
  if (child_pcb == NULL)  {
    return tid;
  }

  /* Add the PCB to the list of PCBs. */
  lock_acquire(&(pcb_list_lock));
  list_push_back(&(pcb_list), &(child_pcb->elem));
  lock_release(&(pcb_list_lock));

  child_retval = child_pcb->retval;

  /* Ensure that LOAD has correctly worked. */
  sema_down(&(child_retval->wait_load));
  bool success_rv = child_retval->load_success;

  /* Load fails */
  if (!success_rv) {
    return -1;
  }

  /* Push the child retval struct into current PCB's children list. */
  list_push_back(&current_pcb->children, &child_retval->elem);
  return tid;
}

void init_fd_table() {
  struct thread* t = thread_current();
  /* Initialize the file descriptor index to stderr. */
  t->pcb->fd_index = 2;
}

/* Checks that pointer to arguments are ok. Checks stack pointer for argc arguments.
 * This includes the file name. */
bool is_valid_args(void* stack_ptr, int argc) {
  int i;
  for (i = 0; i < argc; i += 1) {
    if (!is_valid_ptr(stack_ptr + i * sizeof(void*))) {
      return false;
    }
  }
  return true;
}


/* Checks that the PTR is a valid ptr in current userspace. */
bool is_valid_ptr(void* ptr) {
  uint32_t* pageDir;
  if (ptr == NULL) {
    return false;
  }
  pageDir = thread_current()->pcb->pagedir;
  if (!is_user_vaddr(ptr) || (pagedir_get_page(pageDir, ptr) == NULL)) {
    return false;
  }
  // ensure that the entire pointer boundary (ptr to ptr + 3) is valid.
  ptr += sizeof(void*) - 1;
  if (!is_user_vaddr(ptr) || (pagedir_get_page(pageDir, ptr) == NULL)) {
    return false;
  }
  return true;
}

/* Adds a file descriptor to the current process. */
int add_fd(struct file* theFile) {
  /* File can't be a dummy or NULL */
  if (theFile == NULL
      || theFile->inode == NULL) {
    return -1;
  }

  struct process* process = thread_current()->pcb;
  struct myFile* newFile = (struct myFile*) malloc(sizeof (struct myFile));
  newFile->file_ptr = theFile;
  /* Add file to file descriptor table. */
  list_push_back(&process->file_descriptors, &newFile->elem);

  /* Updates the file descriptor index to the latest. */
  process->fd_index += 1;
  return process->fd_index;
}

struct myFile* get_myFile(int fd) {
  struct process* process = thread_current()->pcb;
  struct list_elem *e;
  struct list* fd_table = &(process->file_descriptors);
  if (fd < 3)
    return NULL; // file is stdin or stdout or stderr.
  int i = 3;
  for (e = list_begin(fd_table); e != list_end(fd_table); e = list_next(e)) {
    if (i++ == fd) { // i++ increments _after_ evaluating
      struct myFile* f = list_entry(e, struct myFile, elem);
      if (f->file_ptr != NULL) // checks that the file descriptor is not closed.
        return f;
      return NULL; // file is closed.
    }
  }
  return NULL; // no such fd exist in the file descriptor table.
}

/* Returns a file from a given fd.
 * If file descriptor didn't exist, has been closed or
 * stdin, stderr, or stdout were passed in will return NULL
 * */
struct file* get_file(int fd) {
  struct myFile* f = get_myFile(fd);
  if (f != NULL) //checks that the file descriptor is not closed or stdin, stdout, stderr.
    return f->file_ptr;
  return NULL;
}

/* Reads to a file descriptor from buffer count times. */
int read_file(int fd, uint32_t* buffer, size_t count) {
  int retval = -1;

  switch (fd) {
      //TODO need to test the stdin

    case STDIN_FILENO:
      for (unsigned int i = 0; i < count; i += 1) {
        buffer[i] = input_getc();
      }
      break;
    case STDOUT_FILENO:
      retval = -1;
      break;

    case 2:
      retval = -1;
      break;

    default: {
      struct file * f = get_file(fd);
      if (f == NULL) {
        //TODO MIGHT HAVE TO PASS AN ERROR OR STH
        return -1;
      }
      retval = file_read(f, buffer, count);
    }
  }
  return retval;
}

/* Writes to a file descriptor from buffer count times. */
int write_file(int fd, uint32_t* buffer, size_t count) {
  int retval = -1;

  switch (fd) {
      //TODO need to test the stdin

    case STDIN_FILENO:
      retval = -1;
      break;
    case STDOUT_FILENO:
      putbuf((char *) buffer, count);
      retval = count;
      break;

    case 2:
      //TODO IMPLEMENT STDERR
      break;

    default: {
      struct file * f = get_file(fd);
      if (f == NULL) {
        //TODO MIGHT HAVE TO PASS AN ERROR OR STH
        return -1;
      }
      retval = file_write(f, buffer, count);
   }
  }
  return retval;
}

int close_file(int fd) {
  struct myFile* f = get_myFile(fd);

  if (f != NULL) {
    if (f->file_ptr != NULL) {
      file_close(f->file_ptr);
      // To indicate that the file descriptor has been close.
      f->file_ptr = NULL;
    }
    return 1;
  } else {
    return -1;
  }
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* args) {
  char* file_name = (char*)(args);
  struct retval* retval = (args + strlen(file_name) + 2);
  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;

  uint32_t fpu_cur[27];

  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  t->pcb = new_pcb;

  /* Initialize process control block */
  success = pcb_success = populate_pcb(new_pcb);

  /* Indicate to parent thread that PCB is ready.*/
  sema_up(&(t->pcb_ready));

  /* Initialize interrupt frame and load executable. */
  int length = strcspn(file_name, " ");
  char file_name_cpy[length + 1];

  if (success) {
    memset(&if_, 0, sizeof if_);
    fpu_init_new(&if_.fpu, &fpu_cur);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;


    memcpy(file_name_cpy, file_name, length);
    file_name_cpy[length] = NULL;
    success = load(file_name_cpy, &if_.eip, &if_.esp);

    /* Indicate to the parent proc that we loaded
     * the program successfully. */
    t->pcb->retval->load_success = success;
    sema_up(&(t->pcb->retval->wait_load));
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;

    /* Indicate to parent that the PCB is fucked */
    sema_up(& (t->pcb_ready));
    free(pcb_to_free);
    return;
  }

  /* For tokenization later... */
  char file_name_copy[strlen(file_name) + 1];
  /* Copy file_name to file_name_copy with null term using strlcpy */
  strlcpy(file_name_copy, file_name, strlen(file_name) + 1);
  

  /* Arguments can take up to a page of memory */
  uint32_t *argv = palloc_get_page(0); int argc = 0;

  char *token, *save_ptr; int _size;
  
  char NULL_TERMINATOR = 0x0;
  for (token = strtok_r(file_name, " ", &save_ptr); token != NULL;
    token = strtok_r(NULL, " ", &save_ptr)) {
      /* Find size of each token to push onto stack */
      _size = strlen(token) + 1;

      /* Decrement user stack pointer */
      if_.esp -= _size;

      /* Store address of token in argument addresses */
      argv[argc++] = if_.esp;

      /* Copy token to user stack */
      memcpy(if_.esp, token, _size);

      /* Null terminate the argv arguments just in case! */
      // memcpy(if_.esp + strlen(token), &NULL_TERMINATOR, 1);
  }

  _size = sizeof(char *) * (argc + 1);

  if_.esp -= _size;
  /* stack-align, addresses are 4B */

  /* We align ESP to anticipate for argc/argv alignment. */
  if_.esp -= ((uint32_t) if_.esp - (2 * sizeof(void *))) % 16;

  // memset(if_.esp, 0x0, align_size);

  /* Add NULL pointer sentinel according to spec */
  argv[argc] = NULL;

  /* Push argv pointers onto stack */
  // if_.esp -= _size;
  memcpy(if_.esp, argv, _size);

  //Free temp argv
  palloc_free_page(argv);

  uint32_t argv_addr = if_.esp;

  /* Push argv */
  if_.esp -= sizeof(void *);
  memcpy(if_.esp, &argv_addr, sizeof(uint32_t *));
  //  *((char ***) if_.esp) = if_.esp + 4;

  /* Push argc */
  if_.esp -= sizeof(void *);
  memcpy(if_.esp, &argc, sizeof(int));
  //  *((int *) if_.esp) = argc;

  /* Push fake "return address" - maintain stack frame structure */
  if_.esp -= sizeof(void *);

  /* Change the process name to get rid of the arguments. */
  strlcpy(t->pcb->process_name, &file_name_cpy, length + 1);
  t->pcb->process_name[length] = NULL;

  /* Clean up. Exit on failure or jump to userspace */
  palloc_free_page(file_name);
  if (!success) {
    // sema_up(&temporary);
    thread_exit();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid) {
  struct list* children;
  struct retval* child_retval = NULL;
  int return_value = -1;
  //sema_down(&temporary);

  children = &(thread_current()->pcb->children);

  /* Find the child process retval. */
  struct list_elem* e;
  for (e = list_begin(children); e != list_end(children); e = list_next(e)) {
    struct retval* _retval = list_entry(e, struct retval, elem);

    // TODO are TID and PID the same? userprog.pdf has a thing
    // on this but not sure...
    if (_retval->tid == child_pid) {
      child_retval = _retval;
    }
  }

  /* Not a valid PID */
  if (child_retval == NULL) {
    return return_value;
  }

  /* Non-blocking tries to acquire the lock to ensure that 
   * we only wait() once. */
  if (lock_held_by_current_thread(&(child_retval->wait_lock))
      || !lock_try_acquire(&(child_retval->wait_lock))) {
    return return_value;
  }


  /* Begin wait for the exit code. */
  sema_down(&(child_retval->wait_sema));

  return_value = child_retval->value;

  lock_acquire(&(child_retval->ref_cnt_lock));
  child_retval->ref_cnt -= 1;

  /* Remove the retval from the parent. */
  list_remove(&(child_retval->elem));


  if (child_retval->ref_cnt <= 0) {
    lock_release(&(child_retval->ref_cnt_lock));
    free(child_retval);
  }  else {
    lock_release(&(child_retval->ref_cnt_lock));
  }

  return return_value;
}

/* Retrieves the PCB given a filename. */
struct process* get_pcb_by_name(char* filename) {
  struct list_elem* e;
  lock_acquire(&(pcb_list_lock));
  for (e = list_begin(&(pcb_list)); e != list_end(&(pcb_list));
      e = list_next(e)) {
    struct process* _pcb = list_entry(e, struct process, elem);
    if (strcmp(_pcb->process_name, filename) == 0) {
      lock_release(&(pcb_list_lock));
      return _pcb;
    }
  }

  lock_release(&(pcb_list_lock));
  return NULL;
}

/* Free the current process's resources. */
void process_exit(int exit_code) {
  struct thread* cur = thread_current();
  uint32_t* pd;

  /* If this thread does not have a PCB, don't worry */
  lock_acquire(&cur->pcb->exit_lock);
  if (cur->pcb == NULL || cur->pcb->exit) {
    lock_release(&cur->pcb->exit_lock);
    thread_exit();
    NOT_REACHED();
  }
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, exit_code);
  cur->pcb->exit = true;
  lock_release(&cur->pcb->exit_lock);
  struct retval* proc_retval = cur->pcb->retval;
  struct list* children_retvals;
  struct list* retvals = &cur->pcb->threads_retvals;

  struct list_elem* e = NULL;
  struct thread_retval* retval;
  sema_up(&cur->retval->join_sema);
  // Go through threads and join on all threads that are still running to signal to exit or yield till it is picked
    for (e = list_begin(retvals); e != list_end(retvals); e = list_next(e)) {
        retval = list_entry(e, struct thread_retval, elem);
        if (retval->tid != cur->tid) {
            //TODO: MONITOR COULD BE BETTER
            if (retval->tid == cur->pcb->main_thread->tid && !retval->is_exited) {
                while (retval->tid == cur->pcb->main_thread->tid && !retval->is_exited) {
                    thread_yield();
                }
            }
            pthread_join(retval->tid);
        }
    }

//    // Release and free all threads return value struct used to join/track created user threads in
//    while (!list_empty(retvals)) {
//        e = list_pop_front(retvals);
//        retval = list_entry(e, struct thread_retval, elem);
//        if (lock_try_acquire(&retval->join_lock)) {
//          lock_release(&retval->join_lock);
//        }
//        free(retval);
//    }


    // free initialized user locks
    while(!list_empty(&cur->pcb->lock_list)) {
        struct list_elem *e = list_pop_front(&cur->pcb->lock_list);
        user_lock* user_lock_ptr = list_entry(e, user_lock, elem);
        list_remove(&user_lock_ptr->elem);
        if (user_lock_ptr->kernel_lock != NULL) {
            // KEEP IN MIND LOCKS NOT HELD BY CURRENT THREAD WILL NOT BE RELEASE BEFORE FREEING.
            if (lock_held_by_current_thread(user_lock_ptr->kernel_lock)){
                lock_release(user_lock_ptr->kernel_lock);
            }
            free(user_lock_ptr->kernel_lock);
        }
        free(user_lock_ptr);
    }

    // free initialized user semaphores
    while(!list_empty(&cur->pcb->sema_list)) {
        struct list_elem *e = list_pop_front(&cur->pcb->sema_list);
        user_semaphore* user_sema_ptr = list_entry(e, user_semaphore, elem);
        list_remove(&user_sema_ptr->elem);
        if (user_sema_ptr->kernel_semaphore != NULL) {
            free(user_sema_ptr->kernel_semaphore);
        }
        free(user_sema_ptr);
    }

  /* Remove the PCB from the list of PCBs. */
  lock_acquire(&(pcb_list_lock));
  list_remove(&(cur->pcb->elem));
  lock_release(&(pcb_list_lock));

  // Close and free the fd list
  while(!list_empty(&cur->pcb->file_descriptors)) {
    struct list_elem *e = list_pop_front(&cur->pcb->file_descriptors);
    struct myFile* f = list_entry(e, struct myFile, elem);
    if (f->file_ptr != NULL) {
      file_close(f->file_ptr);
    }
    free(f);
  }


  /* Synchornization with retval structs*/

  /* Store exit code into retval struct. */
  proc_retval->value = exit_code;

  /* Notify the parent of the waiting process. */
  sema_up(&(proc_retval->wait_sema));

  lock_acquire(&(proc_retval->ref_cnt_lock));
  proc_retval->ref_cnt -= 1;

  /* Free the retval struct if no one is waiting. */
  if (proc_retval->ref_cnt <= 0) {
    lock_release(&(proc_retval->ref_cnt_lock));
    // lock_release(&(proc_retval->wait_lock));
    free(proc_retval);
  } else {
    lock_release(&(proc_retval->ref_cnt_lock));
  }


  /* Decrease ref count of all children retvals.
   * Free if neccesary. */

//  struct list_elem* e;
  children_retvals = &(cur->pcb->children);
  for (e = list_begin(children_retvals); e != list_end(children_retvals);
      e = list_next(e)) {
    struct retval* _retval = list_entry(e, struct retval, elem);

    lock_acquire(&(_retval->ref_cnt_lock));
    _retval->ref_cnt -= 1;

    if (_retval->ref_cnt <= 0) {
      lock_release(&(_retval->ref_cnt_lock));
      free(_retval);
    } else  {
      lock_release(&(_retval->ref_cnt_lock));
    }
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur->pcb;
  cur->pcb = NULL;

  if (thread_current()->waiting_on == &pcb_to_free->filesys_lock) {
    thread_current()->waiting_on = NULL;
  }
  free(pcb_to_free);
  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  file_close(file);
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void (**eip)(void), void** esp, void* arg, pthread_fun tf) {
  uint8_t* kpage;
  uint8_t* esp_l;
  struct thread* t;

  t = thread_current();
  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  esp_l = thread_current()->pcb->last_stack_address;
  if (kpage == NULL) {
    return false;
  }

  while (pagedir_get_page(thread_current()->pcb->pagedir, esp_l) != NULL) {
    esp_l = ((uint8_t *) esp_l) - PGSIZE;
  }
  // update last_stack_address so the next setup_thread doesn't have to start from beginning
  thread_current()->pcb->last_stack_address = esp_l;
  if (!install_page(esp_l, kpage, true)) {
    palloc_free_page(kpage);
    return false;
  }
  t->user_stack = esp_l;
  esp_l += PGSIZE;
  t->kpage = kpage;

  esp_l -= sizeof(void *);
  memcpy((void*) esp_l, &arg, sizeof(void*));
  esp_l -= sizeof(void *);
  memcpy(esp_l, &tf, sizeof(void*));
  esp_l -= sizeof(void *);
  *esp = (void*) esp_l;
  return true;
}

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf, pthread_fun tf, void* arg) {
  tid_t retval;
  struct start_pthread_args s_args;

  s_args.sf = sf;
  s_args.error = true;
  s_args.tf = tf;
  s_args.aux = arg;
  s_args.daddy = thread_current()->pcb;

  sema_init(&s_args.stack_ready, 0);

  retval = thread_create("pthread_child", PRI_DEFAULT, start_pthread, &s_args);

  if (retval == TID_ERROR) {
    return retval;
  }

  /* Wait for the user stack to be ready. */
  sema_down(&s_args.stack_ready);

  return retval;
}

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* aux) {
  struct start_pthread_args* s_args;
  void* stack;
  void* eip;
  struct intr_frame if_;
  uint32_t fpu_cur[27];

  s_args = (struct start_pthread_args *) aux;

  thread_current()->pcb = s_args->daddy;

  struct thread_retval* new_thread_retval = malloc(sizeof(struct thread_retval));

  new_thread_retval->tid = thread_current()->tid;
  lock_init(&new_thread_retval->join_lock);
  sema_init(&new_thread_retval->join_sema, 0);
  new_thread_retval->is_terminated = false;
  new_thread_retval->is_exited = false;
  list_push_front(&thread_current()->pcb->threads_retvals, &new_thread_retval->elem);
  thread_current()->retval = new_thread_retval;

  process_activate();

  memset(&if_, 0, sizeof if_);
  fpu_init_new(&if_.fpu, &fpu_cur);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  /* Setup the stack */
  // bool setup_thread(void (**eip)(void), void** esp, void* arg, pthread_fun tf) {
  if (!(s_args->error = setup_thread(&eip, &stack, s_args->aux, s_args->tf))) {
    // TODO exit thread?
    sema_up(&s_args->stack_ready);
    return;
  }

  if_.esp = stack;
  if_.eip = s_args->sf;


  /* Notify pthread_execute that we're good! */
  sema_up(&s_args->stack_ready);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid) {
    struct thread* t = thread_current();
    struct list* retvals = &t->pcb->threads_retvals;
    struct list_elem* e = NULL;
    bool found = false;
    struct thread_retval* retval;
    
    for (e = list_begin(retvals); e != list_end(retvals); e = list_next(e)) {
        retval = list_entry(e, struct thread_retval, elem);
        if (retval->tid == tid) {
            found = lock_try_acquire(&retval->join_lock);
            break;
        }
    }

    if (!found) {
        return TID_ERROR;
    } else if (retval->is_terminated) {
        lock_release(&retval->join_lock);
        return TID_ERROR;
    } else if (retval->is_exited) {
        lock_release(&retval->join_lock);
        return tid;
    } else {
        sema_down(&retval->join_sema);
        retval->is_terminated = true;
        lock_release(&retval->join_lock);
        return tid;
    }
//TODO: NEED TO FREE RETVAL IN PROCESS_EXIT
}

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {
  struct thread* t;
  t = thread_current();

  //TODO NEED TO CHECK FOR MAIN EXIT
  if (t->pcb->main_thread == t) {
    pthread_exit_main();
    return;
  }
  pagedir_clear_page(t->pcb->pagedir, t->user_stack);
  palloc_free_page(t->kpage);

  /* Free our own retval struct if no one else holds it. */
  sema_up(&t->retval->join_sema);   // notify the waiters
  thread_exit();
}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {
    struct thread* t;
    t = thread_current();
    // TODO: double check resource freeing

    sema_up(&t->retval->join_sema);   // notify the waiters
    if(t->pcb != NULL) {
        struct list* retvals = &t->pcb->threads_retvals;
        struct list_elem* e = NULL;
        struct thread_retval* retval;

        for (e = list_begin(retvals); e != list_end(retvals); e = list_next(e)) {
            retval = list_entry(e, struct thread_retval, elem);
            if (retval->tid != t->tid) {
                pthread_join(retval->tid);
            }
        }
    }
    process_exit(0);
}


bool user_lock_init (char* user_address) {
    int caller = thread_current()->tid; //for debugging

    user_lock* user_lock_ptr = malloc(sizeof(user_lock));
    struct lock* k_lock = malloc(sizeof(struct lock));
    if (user_lock_ptr == NULL || k_lock == NULL) {
        return false;
    }
    lock_init(k_lock);
    user_lock_ptr->kernel_lock = k_lock;
    user_lock_ptr->user_ptr = user_address;
    list_push_front(&thread_current()->pcb->lock_list, &user_lock_ptr->elem);
    return true;
}

struct lock* get_user_lock(char* user_address) {
    struct list* locks = &thread_current()->pcb->lock_list;
    struct list_elem* e = NULL;
    struct user_lock* user_lock_ptr = NULL;
    for (e = list_begin(locks); e != list_end(locks); e = list_next(e)) {
        user_lock_ptr = list_entry(e, user_lock, elem);
        if (user_address == user_lock_ptr->user_ptr)
            return user_lock_ptr;
    }
    return NULL;
}
/* Acquires lock for user thread and includes lock priority donation. */
void user_lock_acquire (char* user_address) {
    int caller = thread_current()->tid; //for debugging

    struct user_lock* user_lock_ptr = get_user_lock(user_address);
    bool found = (user_lock_ptr != NULL);
    if (found) {
        if (!lock_held_by_current_thread(user_lock_ptr->kernel_lock)) {
            lock_acquire(user_lock_ptr->kernel_lock); // don't need to check holder bkz lock_acquire does
            return;
        }
    }
    process_exit(1);
}


/* Releases the lock for user threads and includes priority donation. */
void user_lock_release (char* user_address) {
    int caller = thread_current()->tid; //for debugging

    struct user_lock *user_lock_ptr = get_user_lock(user_address);
    bool found = (user_lock_ptr != NULL);
    if (found) {
        if (lock_held_by_current_thread(user_lock_ptr->kernel_lock)) {
            lock_release(user_lock_ptr->kernel_lock);
            return;
        }
    }
    process_exit(1);
}


bool user_sema_init(char *user_address, unsigned value) {
    user_semaphore *user_sema_ptr = malloc(sizeof(user_semaphore));
    struct semaphore *k_sema = malloc(sizeof(struct semaphore));
    if (user_sema_ptr == NULL || k_sema == NULL) {
        return false;
    }
    sema_init(k_sema, value);
    user_sema_ptr->kernel_semaphore = k_sema;
    user_sema_ptr->user_ptr = user_address;
    list_push_front(&thread_current()->pcb->sema_list, &user_sema_ptr->elem);
    return true;
}


struct semaphore *get_user_sema(char *user_address) {
    struct list *semaphores = &thread_current()->pcb->sema_list;
    struct list_elem *e = NULL;
    struct user_semaphore *user_sema_ptr = NULL;
    for (e = list_begin(semaphores); e != list_end(semaphores); e = list_next(e)) {
        user_sema_ptr = list_entry(e, user_semaphore, elem);
        if (user_address == user_sema_ptr->user_ptr)
            return user_sema_ptr;
    }
    return NULL;
}

/* Acquires semaphore for user thread. */
void user_sema_down(char *user_address) {
    struct user_semaphore *user_sema_ptr = get_user_sema(user_address);
    bool found = (user_sema_ptr != NULL);
    if (found) {
        sema_down(user_sema_ptr->kernel_semaphore); // don't need to check holder bkz lock_acquire does
        return;
    }
    process_exit(1);
}


/* Releases the lock for user threads and includes priority donation. */
void user_sema_up(char *user_address) {
    struct user_semaphore *user_sema_ptr = get_user_sema(user_address);
    bool found = (user_sema_ptr != NULL);
    if (found) {
        sema_up(user_sema_ptr->kernel_semaphore);
        return;
    }
    process_exit(1);
}
