#include "fs/fat32.h"
#include "fs/vfs.h"
#include "drivers/gdb.h"
#include "kernel/semaphore.h"

uint32_t l2b32(uint32_t x)
{
    uint8_t *p = &x;
    return p[0] + p[1] << 8 + p[2] << 16 + p[3] << 24;
}

uint32_t b2l32(uint32_t x)
{
    uint8_t *p = &x;
    return p[3] + p[2] << 8 + p[1] << 16 + p[0] << 24;
}

uint16_t l2b16(uint16_t x)
{
    uint8_t *p = &x;
    return p[0] + p[1] << 8;
}

uint16_t b2l16(uint16_t x)
{
    uint8_t *p = &x;
    return p[3] + p[2] << 8;
}

typedef struct {
    uint32_t fat_begin_lba;
    uint32_t cluster_begin_lba;
    uint32_t sectors_per_cluster;
    uint32_t root_dir_first_cluster;

    semaphore_t *lock;

    gbd_t *disk;
} fat32_t;

inline uint32_t fat32_fat_lookup(fat32_t *fs, uint32_t cluster)
{
    return l2b32(*(fs->fat_begin_lba + cluster * sizeof(uint32_t)));
}

inline fat32_direntry_t *get_next_dir_entry(fat32_t *fs, fat32_direntry_t *entry)
{
    uint8_t *p = entry;

    // end of directory entry
    if (p[31] == 0) {
        return NULL;
    }

    if (p[31] == FAT32_DIR_ENTRY_UNUSED) {
        return get_next_dir_entry(/* the next one */);
    }
}

fs_t fat32_init(gbd_t *disk)
{
    uint32_t addr;
    fs_t *fs;
    semaphore_t *sem;
    gbd_request_t req;
    int r;
    int reserved_sector_count;
    int secs_per_fat;
    int num_fats;

    sem = semaphore_create(1);
    if (sem == NULL) {
        kprintf("fat32_init: could not create a new semaphore.\n");
        return NULL;
    }

    addr = pagepool_get_phys_page();
    if(addr == 0) {
        semaphore_destroy(sem);
        kprintf("fat32_init: could not allocate memory.\n");
        return NULL;
    }
    addr = ADDR_PHYS_TO_KERNEL(addr);

    req.block = 0;
    req.sem = NULL;
    req.buf = ADDR_KERNEL_TO_PHYS(addr);   /* disk needs physical addr */
    r = disk->read_block(disk, &req);
    if(r == 0) {
        semaphore_destroy(sem);
        pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));
        kprintf("fat32_init: Error during disk read. Initialization failed.\n");
        return NULL; 
    }

    // check that file system is FAT32
    if (*(addr+FAT32_SIG_OFFSET) != FAT32_SIGNATURE) {
        semaphore_destroy(sem);
        pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));
        return NULL;
    }

    //memcopy(2, &reserved_sector_count, (int *)(addr+FAT32_RESERVED_SECTOR_COUNT_OFFSET));
    reserved_sector_count = l2b16(*(addr+FAT32_RESERVED_SECTOR_COUNT_OFFSET));

    //memcopy(1, &secs_per_fat, (int *)(addr+FAT32_NUM_FATS_OFFSET));
    secs_per_fat = *(addr+FAT32_NUM_FATS_OFFSET);

    //memcopy(4, &num_fats, (int *)(addr+FAT32_SECS_PER_FAT_OFFSET));
    num_fats = l2b32(*(addr+FAT32_SECS_PER_FAT_OFFSET));

    //memcopy(4, &fs->sectors_per_cluster, (uint32_t *)(addr+FAT32_SECS_PER_CLUS_OFFSET));
    sectors_per_cluster = l2b32(*(addr+FAT32_SECS_PER_CLUS_OFFSET));

    //memcopy(4, &fs->root_dir_first_cluster, (uint32_t *)(addr+FAT32_ROOT_CLUS_OFFSET));
    root_dir_first_cluster = l2b32(*(addr+FAT32_ROOT_CLUS_OFFSET));

    fs->fat_begin_lba = FAT32_MBR_SIZE + reserved_sector_count;
    fs->cluster_begin_lba = FAT32_MBR_SIZE + reserved_sector_count + (num_fats * sectors_per_fat);


    
}
