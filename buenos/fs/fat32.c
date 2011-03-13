#include "fs/fat32.h"
#include "fs/vfs.h"
#include "drivers/gbd.h"
#include "kernel/semaphore.h"
#include "kernel/panic.h"
#include "vm/pagepool.h"

#define DATA_GET(type, data, offset) ((type)*((uint8_t*)data)+offset)

uint32_t l2b32(uint32_t x)
{
    uint8_t *p = &x;
    return p[0] + (p[1] << 8) + (p[2] << 16) + (p[3] << 24);
}

uint32_t b2l32(uint32_t x)
{
    uint8_t *p = &x;
    return p[3] + (p[2] << 8) + (p[1] << 16) + (p[0] << 24);
}

uint16_t l2b16(uint16_t x)
{
    uint8_t *p = &x;
    return p[0] + (p[1] << 8);
}

uint16_t b2l16(uint16_t x)
{
    uint8_t *p = &x;
    return p[3] + (p[2] << 8);
}

typedef struct {
    uint32_t fat_begin_lba;
    uint32_t cluster_begin_lba;
    uint32_t sectors_per_cluster;
    uint32_t root_dir_first_cluster;

    semaphore_t *lock;

    gbd_t *disk;
} fat32_t;

uint32_t fat32_fat_lookup(fat32_t *fat, uint32_t cluster)
{
    uint32_t addr;
    int r;
    gbd_request_t req;
    uint32_t retval;

    addr = pagepool_get_phys_page();
    if(addr == 0) {
        kprintf("fat32_fat_lookup: could not allocate memory.\n");
        return NULL;
    }
    addr = ADDR_PHYS_TO_KERNEL(addr);

    req.block = fat->fat_begin_lba + (cluster / (512 / 32));

    req.sem = NULL;
    req.buf = ADDR_KERNEL_TO_PHYS(addr);   /* disk needs physical addr */
    r = fat->disk->read_block(fat->disk, &req);
    if(r == 0) {
        pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));
        kprintf("fat32_fat_lookup: Error during disk read. Initialization failed.\n");
        return NULL;
    }

    retval = DATA_GET(uint32_t, addr, cluster % (512/32));
}

int next_dir_entry(fat32_t *fat, fat32_direntry_t *entry)
{
    uint32_t addr;
    int r;
    gbd_request_t req;

    addr = pagepool_get_phys_page();
    if (addr == 0) {
        kprintf("fat32_next_dir_entry: could not allocate memory.\n");
        return -1;
    }
    addr = ADDR_PHYS_TO_KERNEL(addr);

    semaphore_P(fat->lock);

    req.block = (entry->cluster * fat->sectors_per_cluster) + entry->sector;
    req.sem = NULL;
    req.buf = ADDR_KERNEL_TO_PHYS(addr);
    r = fat->disk->read_block(fat->disk, &req);
    if(r == 0) {
        semaphore_V(fat->lock);
        pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));
        kprintf("fat32_next_dir_entry: Error during disk read. FAIL\n");
        return -1;
    }

    do {
        if ((++entry->entry) >= (512/32)) {
            entry->entry = 0;
            entry->sector++;

            if (entry->sector >= fat->sectors_per_cluster) {
                entry->sector = 0;
                entry->cluster = fat32_fat_lookup(fat, entry->cluster);
            }

            req.block = (entry->cluster * fat->sectors_per_cluster) + entry->sector;
            req.sem = NULL;
            req.buf = ADDR_KERNEL_TO_PHYS(addr);
            r = fat->disk->read_block(fat->disk, &req);
            if(r == 0) {
                semaphore_V(fat->lock);
                pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));
                kprintf("fat32_next_dir_entry: Error during disk read. FAIL\n");
                return -1;
            }
        }

        stringcopy(entry->sname, (char *)(addr+(entry->entry * 32)),
                   FAT32_SNAME_LEN);
        if (entry->sname[0] == 0) return -1;

        entry->attribs = DATA_GET(fat32_attrib_t, addr, (entry->entry * 32) + 0x0B);
    } while (entry->sname[0] == FAT32_DIR_ENTRY_UNUSED ||
             entry->attribs );

    entry->first_cluster_high = DATA_GET(uint32_t, addr, (entry->entry * 32) + 0x14);
    entry->first_cluster_low = DATA_GET(uint32_t,  addr, (entry->entry * 32) + 0x1A);
    entry->size = DATA_GET(uint32_t, addr, (entry->entry * 32) + 0x1C);

    semaphore_V(fat->lock);

    pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));

    return 0;
}

int search_dir(fat32_t *fat, fat32_direntry_t *entry, int (*pred)(fat32_direntry_t *entry))
{
    while (next_dir_entry(fat, entry) >= 0) {
        if (pred(entry)) {
            return 0;
        }
    }

    return -1;
}

int is_volume_id (fat32_direntry_t *entry)
{
    return (entry->attribs & 8);
}

fs_t *fat32_init(gbd_t *disk)
{
    uint32_t addr;
    fs_t *fs;
    semaphore_t *sem;
    gbd_request_t req;
    int r;
    int reserved_sector_count;
    int secs_per_fat;
    int num_fats;
    fat32_t *fat;
    fat32_direntry_t *direntry;

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
    if (DATA_GET(uint32_t, addr, FAT32_SIG_OFFSET) != FAT32_SIGNATURE) {
        semaphore_destroy(sem);
        pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));
        return NULL;
    }

    // read partition header
    reserved_sector_count = l2b16(DATA_GET(uint32_t, addr, FAT32_RESERVED_SECTOR_COUNT_OFFSET));
    secs_per_fat = l2b32(DATA_GET(uint32_t, addr, FAT32_NUM_FATS_OFFSET));
    num_fats = l2b32(DATA_GET(uint32_t, addr, FAT32_SECS_PER_FAT_OFFSET));

    fat->sectors_per_cluster = l2b32(DATA_GET(uint32_t, addr, FAT32_SECS_PER_CLUS_OFFSET));
    fat->root_dir_first_cluster = l2b32(DATA_GET(uint32_t, addr, FAT32_ROOT_CLUS_OFFSET));
    fat->fat_begin_lba = FAT32_MBR_SIZE + reserved_sector_count;
    fat->cluster_begin_lba = FAT32_MBR_SIZE + reserved_sector_count + (num_fats * secs_per_fat);

    fs = (fs_t *)addr;

    direntry->cluster = 2;
    direntry->sector = 0;
    direntry->entry = 0;
    if (search_dir(fat, direntry, is_volume_id) < 0) {
        KERNEL_PANIC("Volume label not found\n");
    }

    fs->internal = (void *)fat;

    fs->unmount = fat32_unmount;
    fs->open    = fat32_open;
    fs->close   = fat32_close;
    fs->create  = fat32_create;
    fs->remove  = fat32_remove;
    fs->read    = fat32_read;
    fs->write   = fat32_write;
    fs->getfree = fat32_getfree;

    return fs;
}

int fat32_unmount(fs_t *fs)
{
    return 0;
}

int fat32_open(fs_t *fs, char *filename)
{
    return 0;
}

int fat32_close(fs_t *fs, int fileid)
{
    return 0;
}

int fat32_create(fs_t *fs, char *filename, int size)
{
    return 0;
}

int fat32_remove(fs_t *fs, char *filename)
{
    return 0;
}

int fat32_read(fs_t *fs, int fileid, void *buffer, int bufsize, int offset)
{
    return 0;
}

int fat32_write(fs_t *fs, int fileid, void *buffer, int datasize, int offset)
{
    return 0;
}

int fat32_getfree(fs_t *fs)
{
    return 0;
}
