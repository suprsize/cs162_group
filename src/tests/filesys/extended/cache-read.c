/* Tests that seeking past the end of a file and writing will
   properly zero out the region in between. */

#include <syscall.h>

#include <random.h>
#include "tests/lib.h"
#include "tests/main.h"

static char buf[512*69];
static char lol[512*69];

void test_main(void) {
  const char* file_name = "testfile";
  char zero = 0;
  int fd;
  random_bytes(&lol, 512*69);
  random_bytes(&buf, 512*69);
  create(file_name, 512*69);
  fd = open(file_name);
  write(fd, &lol, 512*69);
  close(fd);

  // flush cache
  create("test", 512*69);
  fd = open(file_name);
  write(fd, &buf, 512*69);
  close(fd);

  // should be retrieving from disk
  int res = read_cnt();
  fd = open(file_name);
  read(fd, &buf, 512*64);
  res = read_cnt() - res;

  seek(fd, 0);

  // should be retreiving from cache
  int res2 = read_cnt();
  read(fd, &buf, 512*64);
  close(fd);
  res2 = read_cnt() - res2;

  if (res2 == 0) {
    msg("retrieved from cache!");
  }
}
