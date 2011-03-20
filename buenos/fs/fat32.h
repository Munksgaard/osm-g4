#ifndef FS_FAT32_H
#define FS_FAT32_H

#include "drivers/gbd.h"
#include "fs/vfs.h"
#include "lib/libc.h"
#include "lib/bitmap.h"
#include "lib/types.h"

#define FAT32_BLOCK_SIZE 512
#define FAT32_NUMBER_OF_FATS 2

#define FAT32_MAX_OPEN_FILES 16

fs_t *fat32_init(gbd_t *disk);

int fat32_unmount(fs_t *fs);
int fat32_open(fs_t *fs, char *filename);
int fat32_close(fs_t *fs, int fileid);
int fat32_create(fs_t *fs, char *filename, int size);
int fat32_remove(fs_t *fs, char *filename);
int fat32_read(fs_t *fs, int fileid, void *buffer, int bufsize, int offset);
int fat32_write(fs_t *fs, int fileid, void *buffer, int datasize, int offset);
int fat32_getfree(fs_t *fs);

#endif
