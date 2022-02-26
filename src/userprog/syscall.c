#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

//  printf("System call number: %d\n", args[0]);

  // Brian - Handling syscalls with cases
  // Cases for: Write, Practice, Halt, Exit, Exec, Wait
  switch (args[0]) {

    case SYS_WRITE: {
      int fd, status;
      const void *buffer;
      unsigned size;

      memread_user(f->esp + 4, &fd, sizeof(fd));
      memread_user(f->esp + 8, &buffer, sizeof(buffer));
      memread_user(f->esp + 12, &size, sizeof(size));

      status = write(fd, buffer, size);
      f->eax = (uint32_t) status;
      break;
    }

    case SYS_PRACTICE: {  
      practice();
      NOT_REACHED();
      break;
    }

    case SYS_HALT: {
      halt();
      NOT_REACHED();
      break;
    }

    case SYS_EXIT: {
      int status;
      memread_user(f->esp + 4, &status, sizeof(status));
      exit(status);
      NOT_REACHED();
      break;
    }

    case SYS_EXEC: {
      void *cmd_line;
      memread_user(f->esp + 4, &cmd_line, sizeof(cmd_line));
      int return_code = exec((const char*) cmd_line);
      f->eax = (uint32_t) return_code;
      break;
    }

    case SYS_WAIT: {
      pid_t pid;
      memread_user(f->esp + 4, &pid, sizeof(pid_t));
      int rv = wait(pid);
      f->eax = (uint32_t) rv;
      break;
    }

    default:
      break;
      //
  }

  // Brian -  Process Control Syscall Implmentations
  // Helpers for syscall handlers 

  // Writes into file
  int write (int fd, const void *buffer, unsigned s) {
    int fd = args[1];
      uint32_t* buffer = args[2];
      // TODO valdate the buffer
      size_t count = args[3];
      int retval = write_file(fd, buffer, count);
      f->eax = retval;
  }

  // Increment integer argument by 1
  int practice () {
    f->eax = args[1] + 1;
    return f->eax;
  }

  // Terminates by calling shutdown\_power\_off in devices/shutdown.h
  void halt(void) {
    shutdown_power_off();
  }

  // Terminate current user program and prints exist status of each user program when it exits 
  // %s: exit(%d) where %s is process name and %d is exit code
  void exit (int status) {
    printf("%s: exit(%d)\n", thread_current()->name, status);
    struct process_control_block *pcb = thread_current()->pcb;
    if (pcb != NULL) {
      pcb->exitcode = status;
    }
    else {
      //  process_execute does not properly allocate pages 
    }
    thread_exit();
  }

  // Need to have appropriate synchronization to run the executable given in cmd_line
  // If cannot run or load, return -1
  pid_t exec (const char *cmd_line) {
    check_user((const uint8_t*) cmdline);
    lock_acquire (&filesys_lock); // load() uses filesystem
    pid_t pid = process_execute(cmdline);
    lock_release (&filesys_lock);
    return pid;
  }
  
  //  Waits for child process pid and retrieves the child’s exit status
  int wait(pid_t pid) {
    return process_wait(pid);
  }

}


