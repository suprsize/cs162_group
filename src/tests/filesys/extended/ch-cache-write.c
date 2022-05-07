/* Test the coalescing of writes. */

#include <syscall.h>

#include <random.h>
#include "tests/lib.h"
#include "tests/main.h"

#define BUF_SIZE 512 * 128

static char buf[BUF_SIZE];
static char lol[BUF_SIZE];

void test_main(void) {
  const char* file_name = "testfile";
  char zero = 0;
  int fd;
  random_bytes(&lol, BUF_SIZE);
  random_bytes(&buf, BUF_SIZE);

  // create file
  create(file_name, BUF_SIZE);
  fd = open(file_name);

  // write one byte at a time
  for (unsigned int i = 0; i < BUF_SIZE; i += 1) {
    write(fd, &buf, 1);
  }

  seek(fd, 0);

  // read back one byte at a time
  for (unsigned int i = 0; i < BUF_SIZE; i += 1) {
    read(fd, &buf, 1);
  }

  msg("%d\n", write_cnt());
}
