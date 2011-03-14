#include "fs/fat32.h"
#include "fs/vfs.h"
#include "drivers/gbd.h"
#include "kernel/semaphore.h"
#include "kernel/panic.h"
#include "vm/pagepool.h"

#define DATA_GET(type, addr, offset) (*(type*)(((uint8_t*)addr)+offset))
#define DATA_SET(type, addr, offset, data) memoryset(((uint8_t*)addr) + offset, data, sizeof(type))
#define IS_VALID_FILEID(fid) (fid < CONFIG_MAX_OPEN_FILES+3 && fid >= 2)

char *rtrim(char *str)
{
    char *original = str + strlen(str);
    while (*--original == ' ')
        *(original) = '\0';

    return str;
}

uint32_t l2b32(uint32_t x)
{
    uint8_t *p = (uint8_t *)&x;
    return p[0] + (p[1] << 8) + (p[2] << 16) + (p[3] << 24);
}

uint32_t b2l32(uint32_t x)
{
    uint8_t *p = (uint8_t *)&x;
    return p[3] + (p[2] << 8) + (p[1] << 16) + (p[0] << 24);
}

uint16_t l2b16(uint16_t x)
{
    uint8_t *p = (uint8_t *)&x;
    return p[0] + (p[1] << 8);
}

uint16_t b2l16(uint16_t x)
{
    uint8_t *p = (uint8_t *)&x;
    return p[3] + (p[2] << 8);
}

typedef struct {
    uint32_t fat_begin_lba;
    uint32_t cluster_begin_lba;
    uint32_t sectors_per_cluster;
    uint32_t root_dir_first_cluster;

    semaphore_t *lock;

    fat32_direntry_t *filetable[CONFIG_MAX_OPEN_FILES];

    gbd_t *disk;
} fat32_t;

inline uint32_t cluster2block(fat32_t *fat, uint32_t cluster)
{
    return fat->cluster_begin_lba + (cluster - 2) * fat->sectors_per_cluster;
}

uint32_t fat32_fat_lookup(fat32_t *fat, uint32_t cluster)
{
    uint32_t addr;
    int r;
    gbd_request_t req;
    uint32_t retval;

    addr = pagepool_get_phys_page();
    if(addr == 0) {
        kprintf("fat32_fat_lookup: could not allocate memory.\n");
        return -1;
    }
    addr = ADDR_PHYS_TO_KERNEL(addr);

    uint32_t fat_block = (cluster & ~0x7F) >> 7;
    uint32_t block_entry = cluster & 0x7F;

    req.block = fat->fat_begin_lba + fat_block;

    req.sem = NULL;
    req.buf = ADDR_KERNEL_TO_PHYS(addr);   /* disk needs physical addr */
    r = fat->disk->read_block(fat->disk, &req);
    if(r == 0) {
        pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));
        kprintf("fat32_fat_lookup: Error during disk read. Initialization failed.\n");
        return -1;
    }

    retval = l2b32(DATA_GET(uint32_t, addr, block_entry * 4));
    return retval;
}

int load_direntry(fat32_t *fat, fat32_direntry_t *entry)
{
    uint32_t addr;
    gbd_request_t req;
    int r;

    addr = pagepool_get_phys_page();
    if(addr == 0) {
        pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));
        kprintf("fat32_load_direntry: couldnt allocate page\n");
        return -1;
    }

    addr = ADDR_PHYS_TO_KERNEL(addr);

    req.block = cluster2block(fat, entry->cluster) + entry->sector;
    req.sem = NULL;
    req.buf = ADDR_KERNEL_TO_PHYS(addr);   /* disk needs physical addr */
    r = fat->disk->read_block(fat->disk, &req);
    if(r == 0) {
        pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));
        kprintf("fat32_load_direntry: Error during disk read.\n");
        return -1;
    }

    stringcopy(entry->sname, (char *)(addr+(entry->entry * 32)), FAT32_SNAME_LEN);
    entry->attribs = DATA_GET(fat32_attrib_t, addr, (entry->entry * 32) + 0x0B);
    entry->first_cluster_high = l2b16(DATA_GET(uint16_t, addr, (entry->entry * 32) + 0x14));
    entry->first_cluster_low = l2b16(DATA_GET(uint16_t, addr, (entry->entry * 32) + 0x1a));
    entry->size = l2b32(DATA_GET(uint32_t, addr, (entry->entry * 32) + 0x1C));

    pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));

    return 0;
}

int fat32_fat_cleanup(fat32_t *fat, uint32_t cluster)
{
    uint32_t addr;
    int r;
    gbd_request_t req;
    uint32_t tmp;

    addr = pagepool_get_phys_page();
    if(addr == 0) {
        pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));
        kprintf("fat32_fat_cleanup: couldnt allocate page\n");
        return -1;
    }
    addr = ADDR_PHYS_TO_KERNEL(addr);

    do {
        req.block = fat->fat_begin_lba + (cluster / (512 / 32));

        req.sem = NULL;
        req.buf = ADDR_KERNEL_TO_PHYS(addr);   /* disk needs physical addr */
        r = fat->disk->read_block(fat->disk, &req);
        if(r == 0) {
            pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));
            kprintf("fat32_fat_cleanup: Error during disk read.\n");
            return -1;
        }

        tmp = l2b32(DATA_GET(uint32_t, addr, cluster % (512/32)));
        DATA_SET(uint32_t, addr, cluster % (512/32), 0);

        r = fat->disk->write_block(fat->disk, &req);
        if(r == 0) {
            pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));
            kprintf("fat32_fat_cleanup: Error during disk write.\n");
            return -1;
        }

        cluster = tmp;
    } while (cluster != 0xFFFFFFFF);

    return 0;
}

int next_dir_entry(fat32_t *fat, fat32_direntry_t *entry)
{
    uint32_t addr;
    int r;
    gbd_request_t req;

    addr = pagepool_get_phys_page();
    if (addr == 0) {
        return -1;
    }
    addr = ADDR_PHYS_TO_KERNEL(addr);

    req.block = cluster2block(fat, entry->cluster) + entry->sector;
    req.sem = NULL;
    req.buf = ADDR_KERNEL_TO_PHYS(addr);
    r = fat->disk->read_block(fat->disk, &req);
    if(r == 0) {
        pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));
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

            req.block = cluster2block(fat, entry->cluster) + entry->sector;
            req.sem = NULL;
            req.buf = ADDR_KERNEL_TO_PHYS(addr);
            r = fat->disk->read_block(fat->disk, &req);
            if(r == 0) {
                pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));
                return -1;
            }
        }

        stringcopy(entry->sname, (char *)(addr+(entry->entry * 32)),
                   FAT32_SNAME_LEN);
        if (entry->sname[0] == 0) return -1;

        entry->attribs = DATA_GET(fat32_attrib_t, addr, (entry->entry * 32) + 0x0B);
    } while ((uint8_t)entry->sname[0] == FAT32_DIR_ENTRY_UNUSED ||
             (entry->attribs & 0xf));

    entry->first_cluster_high = l2b16(DATA_GET(uint16_t, addr, (entry->entry * 32) + 0x14));
    entry->first_cluster_low  = l2b16(DATA_GET(uint16_t, addr, (entry->entry * 32) + 0x1A));
    entry->size = l2b32(DATA_GET(uint32_t, addr, (entry->entry * 32) + 0x1C));

    pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));

    return 0;
}

int search_dir(fat32_t *fat, fat32_direntry_t *entry, int (*pred)(fat32_direntry_t *entry))
{
    load_direntry(fat, entry);
    do {
        if (pred(entry)) {
            return VFS_OK;
        }
    } while (next_dir_entry(fat, entry) >= 0);

    return VFS_NOT_FOUND;
}

int search_dir_by_filename(fat32_t *fat, fat32_direntry_t *entry, const char *name)
{
    load_direntry(fat, entry);
    do {
        if (stringcmp(rtrim(entry->sname), name) == 0) {
            return VFS_OK;
        }
    } while (next_dir_entry(fat, entry) >= 0);

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
    fat32_direntry_t direntry;

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
    if (l2b16(DATA_GET(uint16_t, addr, FAT32_SIG_OFFSET)) != FAT32_SIGNATURE) {
        semaphore_destroy(sem);
        pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));
        return NULL;
    }

    fs = (fs_t *)addr;
    fat = (fat32_t *)(addr + sizeof(fs_t));
    fs->internal = (void *)fat;

    fat->lock = sem;
    fat->disk = disk;

    // read partition header
    reserved_sector_count = l2b16(DATA_GET(uint16_t, addr, FAT32_RESERVED_SECTOR_COUNT_OFFSET));
    secs_per_fat = l2b32(DATA_GET(uint32_t, addr, FAT32_SECS_PER_FAT_OFFSET));
    num_fats = DATA_GET(uint8_t, addr, FAT32_NUM_FATS_OFFSET);

    fat->sectors_per_cluster = DATA_GET(uint8_t, addr, FAT32_SECS_PER_CLUS_OFFSET);
    fat->root_dir_first_cluster = l2b32(DATA_GET(uint32_t, addr, FAT32_ROOT_CLUS_OFFSET));
    fat->fat_begin_lba = FAT32_MBR_SIZE + reserved_sector_count;
    fat->cluster_begin_lba = FAT32_MBR_SIZE + reserved_sector_count + (num_fats * secs_per_fat);

    memoryset(fat->filetable, 0, sizeof(fat32_direntry_t *) * CONFIG_MAX_OPEN_FILES);

    direntry.cluster = 2;
    direntry.sector = 0;
    direntry.entry = 0;
    if (search_dir(fat, &direntry, is_volume_id) < 0) {
        KERNEL_PANIC("Volume label not found\n");
    }

    stringcopy(fs->volume_name, direntry.sname, FAT32_SNAME_LEN);

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
    direntry = (fat32_direntry_t*) ADDR_PHYS_TO_KERNEL(pagepool_get_phys_page());

    semaphore_P(fat->lock);
    for (i = 0; i < CONFIG_MAX_OPEN_FILES; ++i) {
        if (fat->filetable[i] == NULL) {
            fat->filetable[i] = direntry;
            direntry->cluster = 2;
            direntry->sector = 0;
            direntry->entry = 0;
            if (search_dir_by_filename(fat, direntry, filename) == VFS_NOT_FOUND) {
                semaphore_V(fat->lock);
                return VFS_NOT_FOUND;
            }

            fat->filetable[i] = direntry;
            semaphore_V(fat->lock);
            return i+3;
        }
    }

    // file table is full
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
    fat32_direntry_t direntry;
    gbd_request_t req;
    int r;
    int addr;

    semaphore_P(fat->lock);

    direntry.cluster = 2;
    direntry.sector = 0;
    direntry.entry = 0;

    if (search_dir_by_filename(fat, &direntry, filename) == VFS_NOT_FOUND) {
        semaphore_V(fat->lock);
        return VFS_NOT_FOUND;
    }

    addr = pagepool_get_phys_page();

    req.block = (direntry.cluster * fat->sectors_per_cluster) + direntry.sector;
    req.buf = addr; // TODO: make a buffer to write from
    req.sem = NULL;
    r = fat->disk->read_block(fat->disk, &req);
    if(r == 0) {
        semaphore_V(fat->lock);
        pagepool_free_phys_page(addr);
        return VFS_ERROR;
    }

    DATA_SET(uint8_t, addr, direntry.entry*32, 0xE5);

    r = fat->disk->write_block(fat->disk, &req);
    if(r == 0) {
        semaphore_V(fat->lock);
        pagepool_free_phys_page(addr);
        return VFS_ERROR;
    }

    if (fat32_fat_cleanup(fat, direntry.cluster) < 0) {
        semaphore_V(fat->lock);
        pagepool_free_phys_page(addr);
        return VFS_ERROR;
    }


    semaphore_V(fat->lock);

    return VFS_OK;
}

int fat32_read(fs_t *fs, int fileid, void *buffer, int bufsize, int offset)
{
    fat32_t *fat = (fat32_t *) fs->internal;
    gbd_request_t req;
    fat32_direntry_t *direntry;
    uint32_t rbuf;
    int r;
    int read = 0;
    uint32_t i;
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

    if (offset < 0 || (uint32_t)offset > direntry->size) {
        semaphore_V(fat->lock);
        return VFS_ERROR;
    }

    bufsize = MIN(bufsize, ((int)direntry->size) - offset);

    if (bufsize == 0) {
        semaphore_V(fat->lock);
        return 0;
    }

    rbuf = pagepool_get_phys_page();

    cluster = (uint32_t)direntry->first_cluster_low + ((uint32_t)direntry->first_cluster_high << 16);
    req.block = cluster2block(fat, cluster);
    req.buf = rbuf;
    req.sem = NULL;

    while (cluster != 0xFFFFFFFF && read < bufsize) {
        for (i = 0; i < fat->sectors_per_cluster; ++i) {

            if (read >= bufsize) { goto finish; }

            r = fat->disk->read_block(fat->disk, &req);
            if (r == 0) {
                pagepool_free_phys_page(rbuf);
                semaphore_V(fat->lock);
                return VFS_ERROR;
            }

            memcopy(MIN(512, bufsize - read), buffer, ADDR_PHYS_TO_KERNEL(rbuf));
            read += MIN(512, bufsize - read);
            buffer = (void *)((uint32_t)buffer + read);
            req.block += 1;
        }

        cluster = fat32_fat_lookup(fat, cluster);
        req.block = cluster2block(fat, cluster);
    }

 finish:

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
