#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/exception.h"
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

  bool invalid_ptr = !is_valid_ptr(args);
  struct lock* file_lock = &thread_current()->pcb->filesys_lock;

  // Stack pointer is invalid.
  if (invalid_ptr) {
    f->eax = -1;
    exit_with_error();
    return;
  }

  switch (args[0]) {

    case SYS_PT_CREATE : {

      if (!is_valid_args(args, 4)
          || !is_valid_ptr(args[1])
          || !is_valid_ptr(args[2])) {
        invalid_ptr = true;
        break;
      }

      tid_t res = pthread_execute(args[1], args[2], args[3]);
      f->eax = res;
      break;
                         }

    case SYS_PT_EXIT: {
      pthread_exit();
      break;
                         }

    case SYS_LOCK_INIT: {
      break;
                         }

    case SYS_LOCK_ACQUIRE: {
      break;
                         }

    case SYS_LOCK_RELEASE: {
      break;
                         }
    case SYS_SEMA_INIT: {
      break;
                         }
    case SYS_SEMA_DOWN: {
      break;
                         }
    case SYS_SEMA_UP: {
      break;
                         }

    case SYS_GET_TID: {
      f->eax = thread_current()->tid;
      break;
                      }

    case SYS_PT_JOIN : {

      if (!is_valid_args(args, 2)) {
        invalid_ptr = true;
        break;
      }

      f->eax = pthread_join(args[1]);
      break;
                         }

    case SYS_CREATE: {
      char *filename = args[1];
      unsigned int initial_size = args[2];
      if (is_valid_ptr(filename)) {
        lock_acquire(file_lock);

        f->eax = filesys_create(filename, initial_size);

        lock_release(file_lock);
        break;
      }
      invalid_ptr = true;
      break;
    }

    case SYS_REMOVE: {
      char * filename = args[1];
      if (is_valid_ptr(filename)) {
        lock_acquire(file_lock);

        f->eax = filesys_remove(filename);

        lock_release(file_lock);
        break;
      }
      invalid_ptr = true;
      break;
    }

    case SYS_OPEN: {
      char *filename = args[1];
      if (is_valid_ptr(filename)) {
        lock_acquire(file_lock);

        struct file* opened_file = filesys_open(filename);

        if (get_pcb_by_name(filename) != NULL) {
          file_deny_write(opened_file);
        }

        f->eax = add_fd(opened_file);

        lock_release(file_lock);
        break;
      }
      invalid_ptr = true;
      break;
                   }

    case SYS_FILESIZE: {
      int fd = args[1];
      lock_acquire(file_lock);

      struct file* file = get_file(fd);
      if (file != NULL) {
        f->eax = file_length(file);

        lock_release(file_lock);
        break;
      }
      invalid_ptr = true; //TODO change to a better name maybe
      lock_release(file_lock);
      break;
    }

     case SYS_READ: {
       int fd = args[1];
       uint32_t* buffer = args[2];
       size_t count = args[3];
       // TODO double check validation
       if (count < 0) {
         f->eax = -1;
         break;
       }
       if (is_valid_ptr(buffer)) {
         lock_acquire(file_lock);

         int bytes_read = read_file(fd, buffer, count);
         f->eax = bytes_read;

         lock_release(file_lock);
         break;
       }
       invalid_ptr = true;
       break;
     }

     case SYS_WRITE: {
       int fd = args[1];
       uint32_t* buffer = args[2];
       size_t count = args[3];
       // TODO double check validation
       if (count < 0) {
         f->eax = -1;
         break;
       }
       if (is_valid_ptr(buffer)) {
         lock_acquire(file_lock);

         int bytes_written = write_file(fd, buffer, count);
         f->eax = bytes_written;

         lock_release(file_lock);
         break;
       }
       invalid_ptr = true;
       break;
     }

     case SYS_SEEK: {
       int fd = args[1];
       unsigned int position = args[2];

       lock_acquire(file_lock);
       struct file* file = get_file(fd);
       if (file != NULL) {
         file_seek(file, position);

         lock_release(file_lock);
         break;
       }
       invalid_ptr = true; //TODO change to a better name maybe

       lock_release(file_lock);
       break;
     }

     case SYS_TELL: {
       int fd = args[1];

       lock_acquire(file_lock);
       struct file* file = get_file(fd);
       if (file != NULL) {
         f->eax = file_tell(file);

         lock_release(file_lock);
         break;
       }
       invalid_ptr = true; //TODO change to a better name maybe

       lock_release(file_lock);
       break;
     }

     case SYS_CLOSE: {
       int fd = args[1];
       //TODO WE ARE HAVE TO FREEING THE FD TABLE WHEN PROCESS CLOSES.
       lock_acquire(file_lock);
       if (close_file(fd) == -1) {
         invalid_ptr = true;
       }
       lock_release(file_lock);
       break;
     }

    case SYS_PRACTICE:
      f->eax = args[1] + 1;
      break;

    case SYS_HALT:
      shutdown_power_off();
      // not reached

    case SYS_EXEC: {
      if (!is_valid_args(args, 2)
          || !is_valid_ptr(args[1])) {
        invalid_ptr = true;
        break;
      }

      f->eax = process_execute((char *) args[1]);
      break;
                   }

    case SYS_WAIT: {

      if (!is_valid_args(args, 2)) {
        invalid_ptr = true;
        break;
      }

      f->eax = process_wait(args[1]);
      break;
                   }

    case SYS_EXIT: {
      f->eax = args[1];
      if (!is_valid_args(args, 2)) {
        invalid_ptr = true;
        break;
      }
//      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
      process_exit(args[1]);
      break;
                   }

    case SYS_COMPUTE_E: {
      if (!is_valid_args(args, 2)) {
        invalid_ptr = true;
        break;
      }
      f->eax = sys_sum_to_e(args[1]);
      break;
                        }

    default:
      break;
  }

  if (invalid_ptr) {
    // We hit invalid buffer so the current process is killed with -1.
    f->eax = -1;
    exit_with_error();
  }
}
