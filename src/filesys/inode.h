#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "threads/synch.h"


struct bitmap;

#define CACHE_SIZE 64

struct cache_entry {
    struct lock entry_lock;               /* Used to synchronize the access to each sector */
    bool valid;                     /* Indicates that the cache entry has valid information of the sector */
    bool dirty;                     /* Indicate that the buffer needs to be written in to sector when evacuated*/
    bool recent;         /* Used to implement clock algorithm */
    block_sector_t sector;          /* the address of sector on disk that is being cached */
    char buffer[BLOCK_SECTOR_SIZE];    /* Saves the raw data and should be write in sector when cache_entry is evacuated */
};

struct cache_entry cache[CACHE_SIZE];   // Cache for buffering disk I/Os
struct lock cache_lock;                 // Global lock for the cache
unsigned int clock_index;               // Current position of clock hand alg for cache policy

void cache_init(void);
void cache_flush(void);
void cache_read(struct block*, block_sector_t, void*);
void cache_write(struct block*, block_sector_t, const void*);

void inode_init(void);
bool inode_create(block_sector_t, off_t);
struct inode* inode_open(block_sector_t);
struct inode* inode_reopen(struct inode*);
block_sector_t inode_get_inumber(const struct inode*);
void inode_close(struct inode*);
void inode_remove(struct inode*);
off_t inode_read_at(struct inode*, void*, off_t size, off_t offset);
off_t inode_write_at(struct inode*, const void*, off_t size, off_t offset);
void inode_deny_write(struct inode*);
void inode_allow_write(struct inode*);
off_t inode_length(const struct inode*);

#endif /* filesys/inode.h */
