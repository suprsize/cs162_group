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

    struct dir* dir = dir_open_root();
    dir_add(dir, ".", ROOT_DIR_SECTOR, true);
    dir_close(dir);
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) { free_map_close(); }

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_length, bool is_dir, bool do_absolute_path) {
  if (*name == '\0')
      return false;
  block_sector_t inode_sector = 0;
  block_sector_t  cwd_sector = thread_current()->pcb->cwd_sector;
  block_sector_t start_sector = cwd_sector;
  if (do_absolute_path)
      start_sector = ROOT_DIR_SECTOR;
  bool is_child_dir = false;
  struct inode* parent_inode = NULL;
  struct inode* child_inode = NULL;
  bool success = false;
  char *name_ptr = name;
  char last_name[NAME_MAX + 1];
  //To support opening the current working directory
  if ((get_next_part(last_name, &name_ptr) == 0) && do_absolute_path){
      name = ".";
  }
    name_ptr = name;
  success = dir_lookup_deep(start_sector, name_ptr, &parent_inode, &child_inode, &is_child_dir);
  if (success) {
      if (child_inode != NULL) {
          inode_close(child_inode);
          inode_close(parent_inode);
          success = false;
      } else {
          struct dir* dir = dir_open(parent_inode);
          // It needs to be a name and not a path
          int read = get_next_part(last_name, &name);
          while(read == 1) {
              read = get_next_part(last_name, &name);
          }
          if (read == -1) {
              // getting last name give error so abort
              dir_close(dir);
              return false;
          }
          success = (dir != NULL) && free_map_allocate(1, &inode_sector) &&
                     inode_create(inode_sector, initial_length, is_dir) && dir_add(dir, last_name, inode_sector, is_dir);
          if ((!success) && (inode_sector != 0)) {
              success = false;
              free_map_release(inode_sector, 1);
          } else {
              if (is_dir) {
                  // Add . and .. to the director
                  struct dir* created_dir = dir_open(inode_open(inode_sector));
                  dir_add(created_dir, ".", inode_sector, true);
                  block_sector_t parent_sector = inode_get_inumber(parent_inode);
                  dir_add(created_dir, "..", parent_sector, true);
                  dir_close(created_dir);
              }
              success = true;
          }
          dir_close(dir);
      }
  }
  if (!success && do_absolute_path)
      success = filesys_create(name, initial_length, is_dir, true);
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
//TODO: NEED TO FREE MYFILES
struct myFile* filesys_open(const char* name, bool do_absolute_path) {
    if (*name == '\0')
        return false;
    struct myFile* new_file = (struct myFile*) malloc(sizeof (struct myFile));
    if (new_file == NULL) {
        return NULL;
    }
    new_file->file_ptr = NULL;
    new_file->dir_ptr = NULL;
    block_sector_t  cwd_sector = thread_current()->pcb->cwd_sector;
    block_sector_t start_sector = cwd_sector;
    if (do_absolute_path)
        start_sector = ROOT_DIR_SECTOR;
    bool is_child_dir = false;
    struct inode *parent_inode = NULL;
    struct inode *child_inode = NULL;
    char *name_ptr = name;
    char last_name[NAME_MAX + 1];
    //To support opening the current working directory
    if ((get_next_part(last_name, &name_ptr) == 0) && do_absolute_path) {
        name = ".";
    }
    name_ptr = name;
    bool success = dir_lookup_deep(start_sector, name_ptr, &parent_inode, &child_inode, &is_child_dir);
    if (success = success && (child_inode != NULL)) {
        if (is_child_dir)
            new_file->dir_ptr = dir_open(child_inode);
        else
            new_file->file_ptr = file_open(child_inode);
        inode_close(parent_inode);
    }
    if ((!success) && (!do_absolute_path)) {
        free(new_file);
        new_file = filesys_open(name, true);
    }
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
//TODO: ABSOLUTE PATH
bool filesys_remove(const char* name, bool do_absolute_path) {
    if (*name == '\0')
        return false;
    block_sector_t cwd_sector = thread_current()->pcb->cwd_sector;
    block_sector_t start_sector = cwd_sector;
    if (do_absolute_path)
        start_sector = ROOT_DIR_SECTOR;
    bool is_child_dir = false;
    struct inode *parent_inode = NULL;
    struct inode *child_inode = NULL;
    char *name_ptr = name;
    char last_name[NAME_MAX + 1];
    //To support opening the current working directory
    if ((get_next_part(last_name, &name_ptr) == 0) && do_absolute_path) {
        name = ".";
    }
    name_ptr = name;
    bool success = dir_lookup_deep(start_sector, name_ptr, &parent_inode, &child_inode, &is_child_dir);
    if (success) {
        char last_name[NAME_MAX + 1];
        name_ptr = name;
        int read = get_next_part(last_name, &name_ptr);
        while (read == 1) {
            read = get_next_part(last_name, &name_ptr);
        }
        block_sector_t child_sector = inode_get_inumber(child_inode);
        success = (read != -1) &&  (child_sector != cwd_sector);
        if (success && is_child_dir) {
            if (!is_opened(child_sector)) {
                struct dir* dir_child = dir_open(child_inode);
                success = success && dir_child != NULL && is_dir_empty(dir_child);
                dir_close(dir_child); // child_inode is closed here
                child_inode = NULL;
            } else {
                success = false;
            }
        }
        if (success) {
            struct dir *parent_dir = dir_open(parent_inode);
            success = (parent_dir != NULL) && (dir_remove(parent_dir, last_name));
            dir_close(parent_dir);
            parent_inode = NULL;
        }
        inode_close(child_inode);
        inode_close(parent_inode);
    }
    if ((!success) && (!do_absolute_path))
        success = filesys_remove(name, true);
  return success;
}


bool filesys_remove2(const char* name) {
    struct dir* dir = dir_open_root();
    bool success = dir != NULL && dir_remove(dir, name);
    dir_close(dir);
    return success;
}

bool filesys_chdir(const char* name, bool do_absolute_path) {
    if (*name == '\0')
        return false;
    block_sector_t cwd_sector = thread_current()->pcb->cwd_sector;
    block_sector_t start_sector = cwd_sector;
    if (do_absolute_path)
        start_sector = ROOT_DIR_SECTOR;
    bool is_child_dir = false;
    struct inode *parent_inode = NULL;
    struct inode *child_inode = NULL;
    char *name_ptr = name;
    char last_name[NAME_MAX + 1];
    //To support opening the current working directory
    if ((get_next_part(last_name, &name_ptr) == 0) && do_absolute_path) {
        name = ".";
    }
    name_ptr = name;
    bool success = dir_lookup_deep(start_sector, name_ptr, &parent_inode, &child_inode, &is_child_dir);
    if (success) {
        if ((child_inode == NULL) || (!is_child_dir)) {
            success = false;
        } else {
            block_sector_t inum = inode_get_inumber(child_inode);
            thread_current()->pcb->cwd_sector = inum;
            success = true;
        }
        inode_close(child_inode);
        inode_close(parent_inode);
    }
    if ((!success) && (!do_absolute_path))
        success = filesys_chdir(name, true);
    return success;
}


bool filesys_isdir(const char* path) {
    block_sector_t start_sector = thread_current()->pcb->cwd_sector;
    bool is_child_dir = false;
    struct inode *parent_inode = NULL;
    struct inode *child_inode = NULL;
    char *name_ptr = path;
    bool success = dir_lookup_deep(start_sector, name_ptr, &parent_inode, &child_inode, &is_child_dir);
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

