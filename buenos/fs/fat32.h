#ifndef BUENOS_FS_FAT32_H
#define BUENOS_FS_FAT32_H

#include "drivers/gbd.h"
#include "fs/vfs.h"

#define FAT32_MBR_SIZE 0
#define FAT32_RESERVED_SECTOR_COUNT_OFFSET 0x0E
#define FAT32_NUM_FATS_OFFSET 0x10
#define FAT32_SECS_PER_FAT_OFFSET 0x24
#define FAT32_SECS_PER_CLUS_OFFSET 0x0D
#define FAT32_ROOT_CLUS_OFFSET 0x2C
#define FAT32_SIG_OFFSET 0x1FE

#define FAT32_BYTES_PER_SECTOR 512

#define FAT32_SIGNATURE 0xAA55
#define FAT32_DIR_ENTRY_UNUSED 0xE5

#define FAT32_SNAME_LEN 11

fs_t *fat32_init(gbt_t *disk);

int fat32_unmount(fs_t *fs);
int fat32_open(fs_t *fs, char *filename);
int fat32_close(fs_t *fs, int fileid);
int fat32_create(fs_t *fs, char *filename, int size);
int fat32_remove(fs_t *fs, char *filename);
int fat32_read(fs_t *fs, int fileid, void *buffer, int bufsize, int offset);
int fat32_write(fs_t *fs, int fileid, void *buffer, int datasize, int offset);
int fat32_getfree(fs_t *fs);

typedef uint8_t fat32_attrib_t;

typedef struct {
    char sname[FAT32_SNAME_LEN];
    fat32_attrib_t attribs;
    uint32_t size;

    // own cluster
    uint32_t cluster;
    uint32_t cluster_offset;
    uint32_t sector_offset;

    // data cluster address
    uint32_t *first_cluster_high;
    uint32_t *first_cluster_low;

    // address to logical page address
    uint32_t page_addr;
} fat32_direntry_t;

#endif
