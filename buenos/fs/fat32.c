#include "fs/fat32.h"
#include "fs/vfs.h"
#include "drivers/gbd.h"
#include "kernel/semaphore.h"
#include "kernel/panic.h"
#include "vm/pagepool.h"

#define DATA_GET(type, data, offset) ((type)*((uint8_t*)data)+offset)

#define IS_VALID_FILEID(fid) (fid < FAT32_MAX_FILES_OPEN+3 && fid >= 2)

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

    fat32_direntry_t* filetable[FAT32_MAX_FILES_OPEN];

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
    } while ((uint8_t)entry->sname[0] == FAT32_DIR_ENTRY_UNUSED ||
             (entry->attribs & 0x1111));

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
            return VFS_OK;
        }
    }

    return VFS_NOT_FOUND;
}

int search_dir_by_filename(fat32_t *fat, fat32_direntry_t *entry, const char *name)
{
    while (next_dir_entry(fat, entry) >= 0) {
        if (stringcmp(entry->sname, name) == 0) {
            return VFS_OK;
        }
    }

    return VFS_NOT_FOUND;
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

    memoryset(fat->filetable, 0, sizeof(fat32_direntry_t *) * FAT32_MAX_FILES_OPEN);

    fs = (fs_t *)addr;
    fs->internal = (void *)fat;

    direntry->cluster = 2;
    direntry->sector = 0;
    direntry->entry = 0;
    if (search_dir(fat, direntry, is_volume_id) < 0) {
        KERNEL_PANIC("Volume label not found\n");
    }

    fat->filetable[3] = direntry;
    fat32_read(fs, 3, fs->volume_name, 16, 0);
    fat->filetable[3] = NULL;

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
    fat32_t *fat;
    fat = (fat32_t *) fs->internal;

    semaphore_P(fat->lock);
    semaphore_destroy(fat->lock);

    pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS((uint32_t) fs));

    return VFS_OK;
}

int fat32_open(fs_t *fs, char *filename)
{
    fat32_t *fat;
    fat32_direntry_t *direntry;
    int i;

    fat = (fat32_t *) fs->internal;

    semaphore_P(fat->lock);

    direntry = pagepool_get_phys_page();
    if (search_dir_by_filename(fat, direntry, filename) == VFS_NOT_FOUND) {
        pagepool_free_phys_page(direntry);
        semaphore_V(fat->lock);
        return VFS_NOT_FOUND;
    }

    for (i = 0; i < FAT32_MAX_FILES_OPEN; ++i) {
        if (fat->filetable[i] == NULL) {
            fat->filetable[i] = direntry;
            semaphore_V(fat->lock);
            return i+3;
        }
    }

    // file table is full
    pagepool_free_phys_page(direntry);
    semaphore_V(fat->lock);
    return VFS_LIMIT;
}

int fat32_close(fs_t *fs, int fileid)
{
    fat32_t *fat;
    fat = (fat32_t *) fs->internal;

    if (!IS_VALID_FILEID(fileid)) {
        return VFS_ERROR;
    }

    semaphore_P(fat->lock);
    pagepool_free_phys_page(fat->filetable[fileid-3]);
    fat->filetable[fileid-3] = NULL;
    semaphore_V(fat->lock);

    return VFS_OK;
}

int fat32_create(fs_t *fs, char *filename, int size)
{
    return 0;
}

int fat32_remove(fs_t *fs, char *filename)
{
    fat32_t *fat = (fat32_t *) fs->internal;
    fat32_direntry_t *direntry;
    gbd_request_t req;
    int r;

    semaphore_P(fat->lock);

    direntry = pagepool_get_phys_page();
    if (search_dir_by_filename(fat, direntry, filename) == VFS_NOT_FOUND) {
        pagepool_free_phys_page(direntry);
        semaphore_V(fat->lock);
        return VFS_NOT_FOUND;
    }

    req.block = (direntry->cluster * fat->sectors_per_cluster) + direntry->sector;
    req.buf = lalalala; // TODO: make a buffer to write from
    req.sem = NULL;
    r = fat->disk->write_block(fat->disk, &req);

    semaphore_V(fat->lock);
    pagepool_free_phys_page(direntry);

    if (r == 0) {
        return VFS_ERROR;
    }
    else {
        return VFS_OK;
    }
}

int fat32_read(fs_t *fs, int fileid, void *buffer, int bufsize, int offset)
{
    fat32_t *fat = (fat32_t *) fs->internal;
    gbd_request_t req;
    fat32_direntry_t *direntry;
    uint32_t rbuf;
    int r;
    int read;
    int i;
    uint32_t cluster;

    if (!IS_VALID_FILEID(fileid)) {
        return VFS_ERROR;
    }

    semaphore_P(fat->lock);

    if (fat->filetable[fileid-3] == NULL) {
        semaphore_V(fat->lock);
        return VFS_NOT_OPEN;
    }

    direntry = fat->filetable[fileid-3];

    if (offset < 0 || offset > direntry->size) {
        semaphore_V(fat->lock);
        return VFS_ERROR;
    }

    bufsize = MIN(bufsize, ((int)direntry->size) - offset);

    if (bufsize == 0) {
        semaphore_V(fat->lock);
        return 0;
    }

    rbuf = pagepool_get_phys_page();

    req.block = cluster = direntry->first_cluster_low + (direntry->first_cluster_high << 4);
    req.buf = rbuf;
    req.sem = NULL;

    while (cluster != 0xFFFFFFFF && read < bufsize) {
        for (i = 0; i < fat->sectors_per_cluster; ++i) {
            r = fat->disk->read_block(fat->disk, &req);

            if (r == 0) {
                pagepool_free_phys_page(rbuf);
                semaphore_V(fat->lock);
                return VFS_ERROR;
            }

            memcopy(r, buffer, rbuf);
            read += r;

            req.block += FAT32_SECTOR_SIZE;
        }

        req.block = cluster = fat32_fat_lookup(fat, cluster);
    }

    pagepool_free_phys_page(rbuf);
    semaphore_V(fat->lock);
    return read;
}

int fat32_write(fs_t *fs, int fileid, void *buffer, int datasize, int offset)
{
    return 0;
}

int fat32_getfree(fs_t *fs)
{
    return 0;
}
