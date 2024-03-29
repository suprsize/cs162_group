#ifndef FILESYS_DIRECTORY_H
#define FILESYS_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/block.h"

/* Maximum length of a file name component.
   This is the traditional UNIX maximum length.
   After directories are implemented, this maximum length may be
   retained, but much longer full path names must be allowed. */
#define NAME_MAX 14

struct inode;

/* A single directory entry. */
struct dir_entry {
  block_sector_t inode_sector; /* Sector number of header. */
  char name[NAME_MAX + 1];     /* Null terminated file name. */
  bool in_use;                 /* In use or free? */
  bool is_dir;                 /* Is the entry for a dir */
};

/* Path String parsing */
int get_next_part(char part[NAME_MAX + 1], const char** srcp);

/* Opening and closing directories. */
bool dir_create(block_sector_t sector, size_t entry_cnt);
struct dir* dir_open(struct inode*);
struct dir* dir_open_root(void);
struct dir* dir_open_cwd(void);
struct dir* dir_reopen(struct dir*);
void dir_close(struct dir*);
struct inode* dir_get_inode(struct dir*);
bool is_dir_empty(struct dir*);
/* Reading and writing. */
bool dir_lookup(const struct dir*, const char* name, struct inode**, bool* is_dir);
bool dir_add(struct dir*, const char* name, block_sector_t, bool is_dir);
bool dir_remove(struct dir*, const char* name);
bool dir_readdir(struct dir*, char name[NAME_MAX + 1]);
bool dir_lookup_deep(block_sector_t, const char*, struct inode** parent_inode, struct inode** inode,
                     bool* is_dir);
#endif /* filesys/directory.h */
