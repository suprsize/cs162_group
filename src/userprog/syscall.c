#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"

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
// TODO argument checking

  bool invalid_ptr = false;
  switch (args[0]) {

    case SYS_OPEN: {
      char *filename = args[1];
      if (is_valid_ptr(filename)) {
        struct file* opened_file = filesys_open(filename);
        //TODO search the file descriptor table for opened_file
        // If it's there, then we change offset to 0. Don't
        // incremenet the file descriptor index. MOH: ACTUALLY don't need to check for double
        // open
        f->eax = add_fd(opened_file);
        break;
      }
      invalid_ptr = true;
      break;
                   }
    case SYS_FILESIZE: {
      int fd = args[1];

    }


    case SYS_REMOVE: {
      char * filename = args[1];
      f->eax = filesys_remove(filename);
      break;
                     }
                     

    case SYS_CREATE: {
      char *filename = args[1];
      unsigned int initial_size = args[2];
      if (is_valid_ptr(filename)) {
        f->eax = filesys_create(filename, initial_size);
        break;
      }
      invalid_ptr = true;
      break;
                     }

    case SYS_PRACTICE:
      f->eax = args[1] + 1;
      break;

    case SYS_HALT:
      shutdown_power_off();
      // not reached

    case SYS_EXEC: {
      f->eax = process_execute((char *) args[1]);
      break;
                   }
    
    case SYS_WAIT: {
      f->eax = process_wait(args[1]);
      break;
                   }

    case SYS_WRITE: {
      int fd = args[1];
      uint32_t* buffer = args[2];
      size_t count = args[3];

      // TODO fix this, shitty way of validaitng

      uint32_t *pd = thread_current()->pcb->pagedir;
      uint32_t *upage = pg_round_down(buffer);

      if (buffer == NULL || (count < 0)) {
        f->eax = -1;
        break;
      }
      uint32_t *pagedir_of_buffer = pagedir_get_page(pd, buffer);

      if ((pagedir_of_buffer == NULL) || !is_user_vaddr(buffer)
          || !is_user_vaddr(buffer + count)) {
        f->eax = -1;
        break;
      }

      int bytes_written = write_file(fd, buffer, count);
      f->eax = bytes_written;
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

  if (invalid_ptr) {
    // We hit invalid buffer so the current process is killed with -1.
    f->eax = -1;
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, f->eax);
    process_exit();
  }
}
