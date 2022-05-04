#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

// TODO implement free map lock
// TODO implement open_inodes lock:w

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
// METADATA contains size, owner, and access control
struct inode_disk {
  off_t length;         /* File size in bytes. */
  uint32_t is_dir;      /* 1: is directory anything else: not director. */
  block_sector_t direct_ptrs [12];
  block_sector_t indirect_ptr;
  block_sector_t doubly_ptr;
  unsigned magic;       /* Magic number. */
  uint32_t unused[111]; /* Not used. */
};

struct indirect_inode {
  block_sector_t blocks[128];
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */

  struct lock resize_lock; /* Must be acquired if we ever want to resize a file. */
  struct lock meta_lock; /* Must be acquired if we ever want to change metadata. */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  char buf [512];
  struct inode_disk* ind;
  int index;
  int l1_index;
  int l2_index;
  int l3_index;
  block_read(fs_device, inode->sector, &buf);
  ind = (struct inode_disk*) buf;

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

      block_read(fs_device, ind->doubly_ptr, &buf);
      l2_arr = (struct indirect_inode *) buf;

      block_read(fs_device, l2_arr->blocks[l2_index], &buf);
      l3_arr = (struct indirect_inode *) buf;

      return l3_arr->blocks[l3_index];
  }

  // singular indirect pointer
  block_read(fs_device, ind->indirect_ptr, &buf);
  return ((struct indirect_inode *)buf)->blocks[l2_index];
}


/* Initializes the inode module. */
void inode_init(void) { list_init(&open_inodes); }

void get_inode_index_from_size (off_t size, int* l1_index, int* l2_index, int* l3_index) {
  ASSERT(size >= 0);
  ASSERT(l1_index != NULL);
  ASSERT(l2_index != NULL);
  ASSERT(l3_index != NULL);

  *l1_index = (int) (size / BLOCK_SECTOR_SIZE);
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
  *l2_index = (int) ((*l1_index) / 128);
  *l3_index = (*l1_index) % 128;
  *l1_index = -1;

  return;
}

/* Resizes a disk inode (ind) with the new_length. */
// TODO keep in mind that inode_disk is updated but NOT flushed to disk.
bool inode_resize (struct inode_disk* ind, off_t new_length) {

  ASSERT(ind != NULL);
  ASSERT(new_length >= 0);
  bool success = true;
  off_t old_length = ind->length;

  // TODO acquire the resize lock.

  // TODO this assertion may not be neccesary
  // and we may need to do something with it.
  ASSERT(new_length >= old_length);

  size_t num_sectors = bytes_to_sectors(new_length - old_length);
  block_sector_t sectors_allocated[num_sectors + 3];

  int i_sector = 0;

  /* Populate the idisk structure if we need it. */
  off_t current_length = old_length + BLOCK_SECTOR_SIZE;
  int l1_index = -1;
  int l2_index = -1;
  int l3_index = -1;

  for (int i = 0; i < num_sectors; i += 1) {
      get_inode_index_from_size(&l1_index, &l2_index, &l3_index, current_length);

      block_sector_t _sector;

      /* Direct pointer */
      if (l1_index != -1) {
          if (!free_map_allocate(1, &_sector)) {
              success = false;
              break;
          }
          ind->direct_ptrs[l1_index] = _sector;

      }

      /* Doubly indirect algorithm */
      else if (l3_index != -1) {
          block_sector_t l2_sector = ind->doubly_ptr;
          block_sector_t l3_sector;
          struct indirect_inode l2_arr;
          struct indirect_inode l3_arr;

          /* Get or create the 2nd level */
          if ((l2_sector == 0) && (!free_map_allocate(1, &l2_sector))) {
              success = false;
              break;
          }

          ind->doubly_ptr = l2_sector;
          block_read(fs_device, l2_sector, &l2_arr);

          /* Get or create the 3rd level */
          l3_sector = l2_arr.blocks[l2_index];

          if (l3_sector == 0 && (!free_map_allocate(1, &l3_sector))) {
              success = false;
              break;
          }

          l2_arr.blocks[l2_index] = l3_sector;
          block_read(fs_device, l3_sector, &l3_arr);
          
          /* Finally allocate the thing. */
          if (!free_map_allocate(1, &l3_arr.blocks[l3_index])) {
              success = false;
              break;
          }

          block_write(fs_device, l3_sector, &l3_arr);
          block_write(fs_device, l2_sector, &l2_arr);
      } else if (l2_index != -1 && (l3_index == -1)) {

          /* Indirect pointer */
          block_sector_t l2_sector = ind->indirect_ptr;
          struct indirect_inode l2_arr;

          if (l2_sector == 0 && (!free_map_allocate(1, &l2_sector))) {
              success = false;
              break;
          }
          ind->indirect_ptr = l2_sector;

          block_read(fs_device, l2_sector, &l2_arr);

          if (!free_map_allocate(1, &l2_arr.blocks[l2_index])) {
              success = false;
              break;
          }

          block_write(fs_device, l2_sector, &l2_arr);
      }

      current_length += BLOCK_SECTOR_SIZE;
  }


  /* Error encountered. must roll back. */
  if (!success) {
  }


  return success;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    if (free_map_allocate(sectors, &disk_inode->start)) {
      block_write(fs_device, sector, disk_inode);
      if (sectors > 0) {
        static char zeros[BLOCK_SECTOR_SIZE];
        size_t i;

        for (i = 0; i < sectors; i++)
          block_write(fs_device, disk_inode->start + i, zeros);
      }
      success = true;
    }
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
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read(fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      free_map_release(inode->sector, 1);
      free_map_release(inode->data.start, bytes_to_sectors(inode->data.length));
    }

    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
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
      block_read(fs_device, sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      block_read(fs_device, sector_idx, bounce);
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

  if (inode->deny_write_cnt)
    return 0;

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
      block_write(fs_device, sector_idx, buffer + bytes_written);
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
        block_read(fs_device, sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      block_write(fs_device, sector_idx, bounce);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  free(bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { return inode->data.length; }
