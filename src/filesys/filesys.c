#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/malloc.h"



/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) { free_map_close(); }

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size, bool is_dir) {
  block_sector_t inode_sector = 0;
  block_sector_t start_sector = thread_current()->pcb->cwd_sector;
  bool is_child_dir = false;
  struct inode* parent_inode = NULL;
  struct inode* child_inode = NULL;
  bool success = false;
  bool done = false;
  char * name_dummy = name;
  char last_name[NAME_MAX + 1];
  if (is_dir) {
      //initial_size passed in is number of entries in the directory not the actual size
      initial_size *= sizeof (struct dir_entry);
  }
  success = dir_lookup_deep(start_sector, name_dummy, &parent_inode, &child_inode, &is_child_dir);
  if (success) {
      if (child_inode != NULL) {
          inode_close(child_inode);
          inode_close(parent_inode);
          success = false;
      } else {
          struct dir* dir = dir_open(parent_inode);
          //TODO: THE NAME NEEDS TO BE A NAME AND NOT A PATH
          while(get_next_part(last_name, &name) > 0) {
          }
          success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                     inode_create(inode_sector, initial_size, is_dir) && dir_add(dir, last_name, inode_sector, is_dir));
          if (!success && inode_sector != 0) {
              success = false;
              free_map_release(inode_sector, 1);
          } else {
              success = true;
              done = true;
          }
          dir_close(dir);
      }
  }
  if (done)
      return true;

  return success;
}


/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create2(const char* name, off_t initial_size, bool is_dir) {
    block_sector_t inode_sector = 0;
    struct dir* dir = dir_open_root();
    bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
               inode_create(inode_sector, initial_size, is_dir) && dir_add(dir, name, inode_sector, false));
    if (!success && inode_sector != 0)
        free_map_release(inode_sector, 1);
    dir_close(dir);
    return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
//TODO: DOESN'T SUPPORT DIR
struct myFile* filesys_open(const char* name) {
    struct myFile* new_file = (struct myFile*) malloc(sizeof (struct myFile));
    if (new_file == NULL) {
        return NULL;
    }
    new_file->file_ptr = NULL;
    new_file->dir_ptr = NULL;

    block_sector_t start_sector = thread_current()->pcb->cwd_sector;
    bool is_child_dir = false;
    struct inode *parent_inode = NULL;
    struct inode *child_inode = NULL;
    char *name_dummy = name;
    bool done = false;
    bool success = dir_lookup_deep(start_sector, name_dummy, &parent_inode, &child_inode, &is_child_dir);
    if (success) {
        if (child_inode == NULL) {
            inode_close(child_inode);
            success = false;
        } else {
            done = true;
            success = true;
            if (is_child_dir)
                new_file->dir_ptr = dir_open(child_inode);
            else
                new_file->file_ptr = file_open(child_inode);
        }
        inode_close(parent_inode);
    }
    if (done)
        return new_file;
    return new_file;
}

struct file* filesys_open2(const char* name) {
  struct dir* dir = dir_open_root();
  struct inode* inode = NULL;
  if (dir != NULL)
    dir_lookup(dir, name, &inode, NULL);
  dir_close(dir);

  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
//TODO: REMOVE DIR
bool filesys_remove(const char* name) {
    block_sector_t start_sector = thread_current()->pcb->cwd_sector;
    bool is_child_dir = false;
    struct inode *parent_inode = NULL;
    struct inode *child_inode = NULL;
    char *name_dummy = name;
    char last_name[NAME_MAX + 1];
    bool done = false;
    bool success = dir_lookup_deep(start_sector, name_dummy, &parent_inode, &child_inode, &is_child_dir);
    if (success) {
        if (child_inode == NULL) {
            inode_close(child_inode);
            success = false;
        } else {
            struct dir* dir = dir_open(parent_inode);
            //TODO: THE NAME NEEDS TO BE A NAME AND NOT A PATH
            while(get_next_part(last_name, &name) > 0) {
            }
            //Don't close parent_inode bkz dir_close does
            success = dir != NULL && dir_remove(dir, last_name);
            dir_close(dir);
        }
    }
  return success;
}


bool filesys_remove2(const char* name) {
    struct dir* dir = dir_open_root();
    bool success = dir != NULL && dir_remove(dir, name);
    dir_close(dir);
    return success;
}

bool filesys_chdir(const char* name) {
    block_sector_t start_sector = thread_current()->pcb->cwd_sector;
    bool is_child_dir = false;
    struct inode *parent_inode = NULL;
    struct inode *child_inode = NULL;
    char *name_dummy = name;
    bool success = dir_lookup_deep(start_sector, name_dummy, &parent_inode, &child_inode, &is_child_dir);
    if (success) {
        if (child_inode == NULL || !is_child_dir) {
            success = false;
        } else {
            block_sector_t inum = inode_get_inumber(child_inode);
            thread_current()->pcb->cwd_sector = inum;
            success = true;
        }
        inode_close(child_inode);
        inode_close(parent_inode);
    }
    return success;
}


bool filesys_isdir(const char* path) {
    block_sector_t start_sector = thread_current()->pcb->cwd_sector;
    bool is_child_dir = false;
    struct inode *parent_inode = NULL;
    struct inode *child_inode = NULL;
    char *name_dummy = path;
    bool success = dir_lookup_deep(start_sector, name_dummy, &parent_inode, &child_inode, &is_child_dir);
    if (success) {
        if (child_inode == NULL || !is_child_dir) {
            success = false;
        } else {
            success = true;
        }
        inode_close(child_inode);
        inode_close(parent_inode);
    }
    return success;
}


/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}

