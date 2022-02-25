#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*) f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

//  printf("System call number: %d\n", args[0]);

  switch (args[0]) {

    case SYS_PRACTICE:
      // TODO validate arguments - We'll write a separate, generic function for this before running syscalls
      f->eax = args[1] + 1;
      break;

    /* James Start */
    
    case SYS_HALT:
      shutdown_power_off();

    case SYS_EXEC:
      f->eax = process_execute((char *) args[1]);
      break;
    
    case SYS_WAIT:
      f->eax = process_wait(args[1]);
      break;

    /* James End */


    case SYS_WRITE: {
      int fd = args[1];
      uint32_t* buffer = args[2];
      // TODO valdate the buffer
      size_t count = args[3];

      int retval = write_file(fd, buffer, count);
      f->eax = retval;
      break;
                    }

    case SYS_EXIT: {
      f->eax = args[1];
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
      process_exit();
      break;
                   }

    default:
      break;
  }
}
