#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/exception.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/block.h"

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

  bool invalid_ptr = !is_valid_ptr(args);

  // Stack pointer is invalid.
  if (invalid_ptr) {
    f->eax = -1;
    exit_with_error();
    return;
  }

  switch (args[0]) {

    case SYS_BLOCK_READS: {
      f->eax = get_total_reads();
      break;
    }

    case SYS_BLOCK_WRITES: {
      f->eax = get_total_writes();
      break;
    }

    case SYS_CREATE: {
      char* filename = args[1];
      unsigned int initial_size = args[2];
      if (is_valid_ptr(filename)) {
        f->eax = filesys_create(filename, initial_size, false, false);
        break;
      }
      invalid_ptr = true;
      break;
    }

    case SYS_REMOVE: {
      char* filename = args[1];
      if (is_valid_ptr(filename)) {
        f->eax = filesys_remove(filename, false);
        break;
      }
      invalid_ptr = true;
      break;
    }

    case SYS_OPEN: {
      //TODO: SUPPORT DIR
      char* filename = args[1];
      if (is_valid_ptr(filename)) {
        struct myFile* opened_file = filesys_open(filename, false);
        if (get_pcb_by_name(filename) != NULL) {
          file_deny_write(opened_file->file_ptr);
        }
        f->eax = add_fd(opened_file);
        break;
      }
      invalid_ptr = true;
      break;
    }

    case SYS_FILESIZE: {
      int fd = args[1];
      struct file* file = get_file(fd);
      if (file != NULL) {
        f->eax = file_length(file);
        break;
      }
      invalid_ptr = true;
      break;
    }

    case SYS_READ: {
      //TODO: ERROR ON DIR
      int fd = args[1];
      uint32_t* buffer = args[2];
      size_t count = args[3];
      if (count < 0) {
        f->eax = -1;
        break;
      }
      if (is_valid_ptr(buffer)) {
        int bytes_read = read_file(fd, buffer, count);
        f->eax = bytes_read;
        break;
      }
      invalid_ptr = true;
      break;
    }

    case SYS_WRITE: {
      //TODO: ERROR ON DIR
      int fd = args[1];
      uint32_t* buffer = args[2];
      size_t count = args[3];
      if (count < 0) {
        f->eax = -1;
        break;
      }
      if (is_valid_ptr(buffer)) {
        int bytes_written = write_file(fd, buffer, count);
        f->eax = bytes_written;
        break;
      }
      invalid_ptr = true;
      break;
    }

    case SYS_SEEK: {
      int fd = args[1];
      unsigned int position = args[2];
      struct file* file = get_file(fd);
      if (file != NULL) {
        file_seek(file, position);
        break;
      }
      invalid_ptr = true;
      break;
    }

    case SYS_TELL: {
      int fd = args[1];
      struct file* file = get_file(fd);
      if (file != NULL) {
        f->eax = file_tell(file);
        break;
      }
      invalid_ptr = true;
      break;
    }

    case SYS_CLOSE: {
      int fd = args[1];
      close_file(fd);
      break;
    }

    case SYS_CHDIR: {
      char* path = args[1];
      f->eax = filesys_chdir(path, false);
      break;
    }

    case SYS_MKDIR: {
      char* filename = args[1];
      //TODO: CHANGE SIZE OF ENTRIES
      unsigned int initial_entries = 15;
      if (is_valid_ptr(filename)) {
        f->eax = filesys_create(filename, initial_entries, true, false);
        break;
      }
      invalid_ptr = true;
      break;
    }

    case SYS_READDIR: {
      int fd = args[1];
      // TODO: NEED VALIDATE THE THE BUFFER
      char* name_buffer = args[2];
      f->eax = do_readdir(fd, name_buffer);
      break;
    }

    case SYS_ISDIR: {
      int fd = args[1];
      f->eax = do_is_dir(fd);
      break;
    }

    case SYS_INUMBER: {
      int fd = args[1];
      f->eax = fd_to_inumber(fd);
      break;
    }

    case SYS_PRACTICE:
      f->eax = args[1] + 1;
      break;

    case SYS_HALT:
      shutdown_power_off();
      // not reached

    case SYS_EXEC: {
      if (!is_valid_args(args, 2) || !is_valid_ptr(args[1])) {
        invalid_ptr = true;
        break;
      }

      f->eax = process_execute((char*)args[1]);
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
      printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
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
