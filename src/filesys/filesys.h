#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "lib/kernel/list.h"


/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0 /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1 /* Root directory file inode sector. */

struct myFile {
    struct file* file_ptr;
    struct dir* dir_ptr;
    struct list_elem elem;
};

/* Block device that contains the file system. */
extern struct block* fs_device;

void filesys_init(bool format);
void filesys_done(void);
bool filesys_create(const char* name, off_t initial_size, bool is_dir);
bool filesys_create2(const char* name, off_t initial_size, bool is_dir);
struct myFile* filesys_open(const char* name);
struct file* filesys_open2(const char* name);

bool filesys_remove(const char* name);
bool filesys_remove2(const char* name);
bool filesys_chdir(const char* name);
bool filesys_isdir(const char* path);


#endif /* filesys/filesys.h */
