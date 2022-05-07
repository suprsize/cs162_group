#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/directory.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44


/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
static struct lock open_inodes_lock;

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
// METADATA contains size, owner, and access control
struct inode_disk {
  struct lock* resize_lock;
  off_t length;    /* File size in bytes. */
  uint32_t is_dir; /* 1: is directory anything else: not director. */
  block_sector_t direct_ptrs[12];
  block_sector_t indirect_ptr;
  block_sector_t doubly_ptr;
  unsigned magic;       /* Magic number. */
  uint32_t unused[110]; /* Not used. */
};

struct indirect_inode {
  block_sector_t blocks[128];
};

void get_inode_index_from_size(off_t size, int* l1_index, int* l2_index, int* l3_index) {
  ASSERT(size >= 0);
  ASSERT(l1_index != NULL);
  ASSERT(l2_index != NULL);
  ASSERT(l3_index != NULL);

  *l1_index = (int)(size / BLOCK_SECTOR_SIZE);
  *l2_index = -1;
  *l3_index = -1;

  // direct pointer
  if (*l1_index <= 11)
    return;

  // indirect pointer
  *l1_index -= 12;
  *l2_index = *l1_index;
  if (*l2_index <= 127) {
    *l1_index = -1;
    return;
  }

  *l1_index -= 128;

  // doubly pointer
  *l2_index = (int)((*l1_index) / 128);
  *l3_index = (*l1_index) % 128;
  *l1_index = -1;

  return;
}
unsigned int do_clock_alg(void);
int find_cache_entry(struct block*, block_sector_t sector_num);

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct list_elem elem; /* Element in inode list. */
  block_sector_t sector; /* Sector number of disk location. */
  int open_cnt;          /* Number of openers. */
  bool removed;          /* True if deleted, false otherwise. */
  int deny_write_cnt;    /* 0: writes ok, >0: deny writes. */

  struct lock meta_lock; /* Must be acquired if we ever want to change metadata. */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  char buf[512];
  struct inode_disk* ind;
  int l1_index;
  int l2_index;
  int l3_index;
  cache_read(fs_device, inode->sector, &buf);
  ind = (struct inode_disk*)buf;

  /* We don't have data past the given size. */
  if (pos > ind->length)
    return -1;

  get_inode_index_from_size(pos, &l1_index, &l2_index, &l3_index);

  // direct pointer
  if (l1_index != -1)
    return ind->direct_ptrs[l1_index];

  // doubly indirect
  if (l3_index != -1) {
    struct indirect_inode* l2_arr;
    struct indirect_inode* l3_arr;

    cache_read(fs_device, ind->doubly_ptr, &buf);
    l2_arr = (struct indirect_inode*)buf;

    cache_read(fs_device, l2_arr->blocks[l2_index], &buf);
    l3_arr = (struct indirect_inode*)buf;

    return l3_arr->blocks[l3_index];
  }

  // singular indirect pointer
  cache_read(fs_device, ind->indirect_ptr, &buf);
  return ((struct indirect_inode*)buf)->blocks[l2_index];
}

/* Initializes the inode module. */
void inode_init(void) {
  lock_init(&open_inodes_lock);
  list_init(&open_inodes);
}

/* Resizes a disk inode (ind) with the new_length. */
bool inode_resize(struct inode_disk* ind, off_t new_length) {
  /* direct pointers */
  for (int i = 0; i < 12; i += 1) {
    if (new_length <= BLOCK_SECTOR_SIZE * i && ind->direct_ptrs[i] != 0) {
      free_map_release(ind->direct_ptrs[i], 1);
      ind->direct_ptrs[i] = 0;
    } else if (new_length > BLOCK_SECTOR_SIZE * i && ind->direct_ptrs[i] == 0) {
      if (!free_map_allocate(1, &ind->direct_ptrs[i])) {
        inode_resize(ind, ind->length);
        return false;
      }
    }
  }

  /* indirect pointers */
  // we don't need to shrink or grow.
  if ((ind->indirect_ptr == 0) && (new_length <= BLOCK_SECTOR_SIZE * 12)) {
    ind->length = new_length;
    return true;
  }

  block_sector_t* indir_inode = calloc(128, sizeof(block_sector_t));
  memset(indir_inode, 0, BLOCK_SECTOR_SIZE);

  // need to grow
  if (ind->indirect_ptr == 0) {
    if (!free_map_allocate(1, &ind->indirect_ptr)) {
      inode_resize(ind, ind->length);
      free(indir_inode);
      return false;
    }
  } else {
    cache_read(fs_device, ind->indirect_ptr, indir_inode);
  }

  // we traverse the indirect pointer tree ;)
  for (int i = 0; i < 128; i += 1) {
    // shrink
    if ((new_length <= (12 + i) * BLOCK_SECTOR_SIZE) && (indir_inode[i] != 0)) {
      free_map_release(indir_inode[i], 1);
      indir_inode[i] = 0;

      // grow
    } else if ((new_length > (12 + i) * BLOCK_SECTOR_SIZE) && (indir_inode[i] == 0)) {
      if (!free_map_allocate(1, &indir_inode[i])) {
        // we write so the resize can deallocate these things.
        cache_write(fs_device, ind->indirect_ptr, indir_inode);
        inode_resize(ind, ind->length);
        free(indir_inode);
        return false;
      }
    }
  }

  // check if we still need the indirect-ptr
  if ((ind->indirect_ptr != 0) && (new_length <= 12 * BLOCK_SECTOR_SIZE)) {
    free_map_release(ind->indirect_ptr, 1);
    ind->indirect_ptr = 0;
  } else {
    cache_write(fs_device, ind->indirect_ptr, indir_inode);
  }

  free(indir_inode);

  /* Doubly indirect pointer */

  if ((ind->doubly_ptr == 0) && (new_length <= (12 + 128) * BLOCK_SECTOR_SIZE)) {
    ind->length = new_length;
    return true;
  }

  // base level of the doubly pointer
  block_sector_t* l2_arr = calloc(128, sizeof(block_sector_t));
  ASSERT(l2_arr != NULL);

  memset(l2_arr, 0, BLOCK_SECTOR_SIZE);

  // create the base doubly pointer.
  if (ind->doubly_ptr == 0 && (!free_map_allocate(1, &ind->doubly_ptr))) {
    ind->doubly_ptr = 0;
    inode_resize(ind, ind->length);
    free(l2_arr);
    return false;
  } else {
    // read that shit in
    cache_read(fs_device, ind->doubly_ptr, l2_arr);
  }

  // traverse the doubly pointer tree
  for (int i = 0; i < 128; i += 1) {
    block_sector_t* l3_arr = calloc(128, sizeof(block_sector_t));
    ASSERT(l3_arr != NULL);

    // we don't need to traverse anymore
    if (new_length <= ((12 + 128 + (128 * i)) * BLOCK_SECTOR_SIZE) && (l2_arr[i] == 0)) {
      free(l3_arr);
      break;
    }

    // grow.
    if ((l2_arr[i] == 0) && (new_length > (12 + 128 + (128 * i)) * BLOCK_SECTOR_SIZE)) {
      if (!free_map_allocate(1, &l2_arr[i])) {
        cache_write(fs_device, ind->doubly_ptr, l2_arr);
        free(l3_arr);
        free(l2_arr);
        inode_resize(ind, ind->length);
        return false;
      }
    }

    cache_read(fs_device, l2_arr[i], l3_arr);

    for (int j = 0; j < 128; j += 1) {
      // shrink
      if ((new_length <= (12 + 128 + (128 * i) + j) * BLOCK_SECTOR_SIZE) && l3_arr[j] != 0) {
        free_map_release(l3_arr[j], 1);
        l3_arr[j] = 0;
      } else if ((new_length > ((12 + 128 + (128 * i) + j) * BLOCK_SECTOR_SIZE)) &&
                 (l3_arr[j] == 0)) {
        if (!free_map_allocate(1, &l3_arr[j])) {
          cache_write(fs_device, ind->doubly_ptr, l2_arr);
          cache_write(fs_device, l2_arr[i], l3_arr);
          inode_resize(ind, ind->length);
          free(l2_arr);
          free(l3_arr);
          return false;
        }
      }
    }

    // shrink/remove the l3_arr if needed
    if ((new_length <= (12 + 128 + (128 * i)) * BLOCK_SECTOR_SIZE) && (l2_arr[i] != 0)) {
      free_map_release(l2_arr[i], 1);
      l2_arr[i] = 0;
    } else {
      cache_write(fs_device, l2_arr[i], l3_arr);
    }
    free(l3_arr);
  }

  if ((ind->doubly_ptr != 0) && (new_length <= (128 + 12) * BLOCK_SECTOR_SIZE)) {
    free_map_release(ind->doubly_ptr, 1);
    ind->doubly_ptr = 0;
  } else {
    cache_write(fs_device, ind->doubly_ptr, l2_arr);
  }

  ind->length = new_length;
  free(l2_arr);
  return true;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length, bool is_dir) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
       one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    disk_inode->resize_lock = malloc(sizeof(struct lock));
    ASSERT(disk_inode->resize_lock != NULL);
    lock_init(disk_inode->resize_lock);
    lock_acquire(disk_inode->resize_lock);

    disk_inode->is_dir = is_dir;
    disk_inode->magic = INODE_MAGIC;
    if (is_dir) {
      //initial_size passed in is number of entries in the directory not the actual size
      length *= sizeof(struct dir_entry);
    }
    success = inode_resize(disk_inode, length);

    if (success)
      cache_write(fs_device, sector, disk_inode);
    lock_release(disk_inode->resize_lock);
    free(disk_inode);
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  lock_acquire(&open_inodes_lock);
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      lock_release(&open_inodes_lock);
      return inode;
    }
  }
  lock_release(&open_inodes_lock);

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  lock_init(&inode->meta_lock);
  lock_acquire(&inode->meta_lock);
  lock_acquire(&open_inodes_lock);
  list_push_front(&open_inodes, &inode->elem);
  lock_release(&open_inodes_lock);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_release(&inode->meta_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL) {
    lock_acquire(&inode->meta_lock);
    inode->open_cnt++;
    lock_release(&inode->meta_lock);
  }
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) {
  if (inode == NULL)
    return -1;
  lock_acquire(&inode->meta_lock);
  block_sector_t inumber = inode->sector;
  lock_release(&inode->meta_lock);
  return inumber;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  lock_acquire(&inode->meta_lock);
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      struct inode_disk ind;
      cache_read(fs_device, inode->sector, &ind);
      lock_acquire(ind.resize_lock);
      inode_resize(&ind, 0);
      free_map_release(inode->sector, 1);
    }
    lock_release(&inode->meta_lock);
    free(inode);
  } else {
    lock_release(&inode->meta_lock);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  lock_acquire(&inode->meta_lock);
  inode->removed = true;
  lock_release(&inode->meta_lock);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {

  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t* bounce = NULL;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);

    /* If we read past EOF, then don't return anything. */
    if (sector_idx == -1) {
      break;
    }

    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      cache_read(fs_device, sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      cache_read(fs_device, sector_idx, bounce);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  free(bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t* bounce = NULL;
  struct inode_disk* ind;

  if (inode->deny_write_cnt)
    return 0;

  char buf[BLOCK_SECTOR_SIZE];
  cache_read(fs_device, inode->sector, buf);
  ind = (struct inode_disk*)buf;

  if ((ind->length < size + offset)) {
    lock_acquire(ind->resize_lock);
    cache_read(fs_device, inode->sector, buf);
    if ((ind->length < size + offset) && (!inode_resize(ind, size + offset))) {
      lock_release(ind->resize_lock);
      return 0;
    }
    lock_release(ind->resize_lock);
  }
  cache_write(fs_device, inode->sector, ind);

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);

    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      cache_write(fs_device, sector_idx, buffer + bytes_written);
    } else {
      /* We need a bounce buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }

      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left)
        cache_read(fs_device, sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      cache_write(fs_device, sector_idx, bounce);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  free(bounce);

  cache_write(fs_device, inode->sector, ind);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  lock_acquire(&inode->meta_lock);
  inode->deny_write_cnt++;
  lock_release(&inode->meta_lock);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  lock_acquire(&inode->meta_lock);
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  lock_release(&inode->meta_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) {
  struct inode_disk ind;
  cache_read(fs_device, inode->sector, &ind);
  return ind.length;
}

void cache_init() {
  lock_init(&cache_lock);
  lock_acquire(&cache_lock);
  clock_index = 0;
  for (int i = 0; i < CACHE_SIZE; i++) {
    cache[i].valid = false;
    cache[i].dirty = false;
    cache[i].recent = false;
    lock_init(&cache[i].entry_lock);
  }
  lock_release(&cache_lock);
}

// Must hold the global Lock before calling this function
unsigned int do_clock_alg() {
  struct cache_entry* entry = &cache[clock_index];
  while (entry->recent) {
    entry->recent = false;
    clock_index = (clock_index + 1) % CACHE_SIZE;
    entry = &cache[clock_index];
  }
  unsigned int empty_spot = clock_index;
  clock_index = (clock_index + 1) % CACHE_SIZE;
  return empty_spot;
}

// Searches for the cache entry with the given sector. If it could not find, it will return -1.
int find_cache_entry(struct block* drive, block_sector_t sector_num) {
  lock_acquire(&cache_lock);
  for (int i = 0; i < CACHE_SIZE; i++) {
    if (cache[i].valid && cache[i].sector == sector_num) {
      lock_release(&cache_lock);
      lock_acquire(&cache[i].entry_lock);
      return i;
    }
  }
  // Sector is not in the cache, bring it into cache
  int evict = do_clock_alg();
  struct cache_entry* entry = &cache[evict];
  lock_acquire(&cache[evict].entry_lock);
  // Prep the section so that when another process looks for the same sector it could find it and wait for it
  bool occupied = entry->valid && entry->dirty;
  block_sector_t old_sector = entry->sector;
  entry->sector = sector_num;
  entry->valid = true;
  entry->dirty = false;
  entry->recent = true;
  // Release global lock
  lock_release(&cache_lock);
  // Update the buffer for the new sector
  if (occupied)
    block_write(drive, old_sector,
                entry->buffer); //DON'T KNOW IF WE NEED THE & FOR BUFFER----------
  block_read(drive, sector_num, entry->buffer);
  return evict;
}

void cache_read(struct block* drive, block_sector_t sector_idx, void* buffer) {
  int cache_idx = find_cache_entry(drive, sector_idx);
  struct cache_entry* entry = &cache[cache_idx];
  while (entry->sector != sector_idx) {
    lock_release(&entry->entry_lock);
    cache_idx = find_cache_entry(drive, sector_idx);
    entry = &cache[cache_idx];
  }
  // Update flags
  lock_acquire(&cache_lock);
  entry->recent = true;
  lock_release(&cache_lock);

  // Copy the data into user buffer
  memcpy(buffer, entry->buffer, BLOCK_SECTOR_SIZE);
  lock_release(&entry->entry_lock);
}

void cache_write(struct block* drive, block_sector_t sector_idx, const void* buffer) {
  int cache_idx = find_cache_entry(drive, sector_idx);
  struct cache_entry* entry = &cache[cache_idx];
  while (entry->sector != sector_idx) {
    lock_release(&entry->entry_lock);
    cache_idx = find_cache_entry(drive, sector_idx);
    entry = &cache[cache_idx];
  }
  // Update flags
  lock_acquire(&cache_lock);
  entry->dirty = true;
  entry->recent = true;
  lock_release(&cache_lock);

  // Copy the data cache
  memcpy(entry->buffer, buffer, BLOCK_SECTOR_SIZE);
  lock_release(&entry->entry_lock);
}

void cache_flush() {
  lock_acquire(&cache_lock);
  for (int i = 0; i < CACHE_SIZE; i++) {
    if (cache[i].valid && cache[i].dirty) {
      cache[i].dirty = false;
      lock_release(&cache_lock);
      lock_acquire(&cache[i].entry_lock);
      block_write(fs_device, cache[i].sector, cache[i].buffer);
      lock_release(&cache[i].entry_lock);
      lock_acquire(&cache_lock);
    }
  }
  lock_release(&cache_lock);
}
