#include "fs/fat32.h"
#include "kernel/kmalloc.h"
#include "kernel/assert.h"
#include "vm/pagepool.h"
#include "drivers/gbd.h"
#include "fs/vfs.h"
#include "fs/tfs.h"
#include "lib/libc.h"
#include "lib/bitmap.h"

#define FAT32_ENTRY_SIZE 32
#define FAT32_MARK_EOC 0x0FFFFFF8

#define FAT32_MAGIC_1 0x55
#define FAT32_MAGIC_2 0xAA

#define FAT32_ENTRY_FREE 0xE5
#define FAT32_ENTRY_END 0x00

#define FAT32_ENTRIES_PER_BLOCK (FAT32_BLOCK_SIZE/FAT32_ENTRY_SIZE)
#define FAT32_VOLUMENAME_MAX 11

enum file_attributes {
    ATTR_READ_ONLY = 1,
    ATTR_HIDDEN = 2,
    ATTR_SYSTEM = 4,
    ATTR_VOLUME_ID = 8,
    ATTR_DIRECTORY = 16,
    ATTR_ARCHIVE = 32
};

#define ATTR_LONG_NAME (ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID)
#define ATTR_LONG_NAME_MASK (ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID | ATTR_DIRECTORY | ATTR_ARCHIVE)

typedef struct {
    char filename[FAT32_VOLUMENAME_MAX];
    uint8_t attributes;
    int32_t first_cluster;
    int32_t file_size;
} dir_entry_t;

typedef struct {
    char filename[VFS_NAME_LENGTH];
    uint8_t attributes;
    int32_t file_size;
    uint32_t first_cluster;
    uint32_t short_entry_cluster;
    uint32_t short_entry_idx;
} file_identification_t;

typedef struct {
    file_identification_t ident;
    int refcount;
} open_file_t;

typedef struct {
    uint8_t  blocks_per_cluster;
    uint16_t reserved_blocks;
    uint32_t blocks_per_fat;
    uint32_t root_first_cluster;
    uint32_t total_blocks;
} fat32_volumeid_t;

typedef struct {
    fat32_volumeid_t volumeid;
    int32_t clusters_begin_block;
    int32_t fat_begin_block;
    int32_t last_cluster;
    gbd_t *disk;
    semaphore_t *lock;
    uint32_t hasblock;
    uint32_t last_ret;
    open_file_t open_files_table[FAT32_MAX_OPEN_FILES];
    uint8_t *buffer_block;
} fat32_t;

/**
 * Convert the given cluster number to a corresponding block number.
 *
 * @param cluster The cluster to convert.
 *
 * @return The block number..
 */
uint32_t cluster_to_block(fat32_t *fat32, uint32_t cluster)
{
    return fat32->clusters_begin_block +
        (cluster - 2) * fat32->volumeid.blocks_per_cluster;
}

/**
 * Convert 32-bit little-endian to 32-bit big-endian.
 */
uint32_t l2b32(uint32_t x)
{
    uint8_t *res = (uint8_t*)&x;
    return res[0]+(res[1]<<8)+(res[2]<<16)+(res[3]<<24);
}

/**
 * Convert 16-bit little-endian to 16-bit big-endian.
 */
uint16_t l2b16(uint16_t x)
{
    uint8_t *res = (uint8_t*)&x;
    return res[0]+(res[1]<<8);
}

/**
 * Convert 32-bit big-endian to 32-bit little-endian.
 */
uint32_t b2l32(uint32_t x)
{
    uint8_t *res = (uint8_t*)&x;
    return (res[3]<<24)+(res[2]<<16)+(res[1]<<8)+res[0];
}

/**
 * Convert 16-bit big-endian to 16-bit little-endian.
 */
uint16_t b2l16(uint16_t x)
{
    uint8_t *res = (uint8_t*)&x;
    return (res[1]<<8)+res[0];
}

/**
 * Read a block from the file system and store it in fat32->buffer_block.
 *
 * @param block Number of the disk block to read.
 *
 * @return The return code of the I/O call.
 */
int readblock(fat32_t *fat32, uint32_t block)
{
    if (fat32->hasblock == block) { /* Simple cache mechanism */
        return fat32->last_ret;
    } else {
        gbd_request_t req;
        req.block = block;
        req.sem = NULL;
        req.buf = ADDR_KERNEL_TO_PHYS((uint32_t)fat32->buffer_block);
        fat32->hasblock = block;
        return fat32->last_ret
            = fat32->disk->read_block(fat32->disk,&req);
    }
}

/**
 * Write the buffer in fat32->buffer_block to a disk block.
 *
 * @param block The number of the disk block that will be overwritten.
 *
 * @return The return code of the I/O call.
 */
int writeblock(fat32_t *fat32, uint32_t block)
{
    gbd_request_t req;
    req.block = block;
    req.sem = NULL;
    req.buf = ADDR_KERNEL_TO_PHYS((uint32_t)fat32->buffer_block);
    fat32->hasblock = block;
    return fat32->last_ret
        = fat32->disk->write_block(fat32->disk,&req);
}

/**
 * Perform lookup in FAT.
 *
 * @param cluster The cluster number for which the FAT lookup is performed.
 *
 * @return Number of the next cluster in the cluster chain.  Greater
 * than FAT32_MARK_EOC if there are no following clusters, and zero if
 * the given cluster is free.
 */
uint32_t fat_lookup(fat32_t *fat32, uint32_t cluster)
{
    uint32_t fat_block = (cluster & ~0x7F) >> 7;
    uint32_t block_entry = cluster & 0x7F;

    KERNEL_ASSERT(cluster >= 2);

    readblock(fat32, fat32->fat_begin_block+fat_block);
    return 0x0FFFFFFF & l2b32(((uint32_t*)fat32->buffer_block)[block_entry]);
}

/**
 * Write value to the FAT.
 *
 * @param cluster The entry in the FAT that will be updated.
 *
 * @param val The new value for the given entry in the FAT.  Note that
 * the upper four bits are not written, as per the FAT specification.
 *
 * @return The return code of the I/O call.
 */
void fat_write(fat32_t *fat32, uint32_t cluster, uint32_t val)
{
    uint32_t fat_block = (cluster & ~0x7F) >> 7;
    uint32_t block_entry = cluster & 0x7F;

    KERNEL_ASSERT(cluster >= 2);

    readblock(fat32, fat32->fat_begin_block+fat_block);
    val |= ((uint32_t*)fat32->buffer_block)[block_entry] & 0xF0000000;
    ((uint32_t*)fat32->buffer_block)[block_entry] = b2l32(val);
    writeblock(fat32, fat32->fat_begin_block+fat_block);
}

/**
 * Find and return a free cluster, updating the FAT to indicate that
 * the cluster is no longer free.
 *
 * @param cluster If non-zero, the FAT entry for this cluster will be
 * updated such that it points at the newly allocated cluster.
 *
 * @return The newly allocated cluster, or zero if there are no free
 * clusters.
 */
uint32_t fat_alloc(fat32_t *fat32, uint32_t cluster)
{
    int candidate;

    for (candidate = 2; candidate <= fat32->last_cluster; candidate++) {
        if (fat_lookup(fat32, candidate) == 0) {
            fat_write(fat32, candidate, FAT32_MARK_EOC);
            if (cluster > 0) {
                fat_write(fat32, cluster, candidate);
            }
            break;
        }
    }
    if (candidate > fat32->last_cluster) {
        return 0;;
    } else {
        return candidate;
    }
}

/**
 * Either return the cluster that follows the given cluster according
 * to the FAT, or allocate a new cluster and return that.
 *
 * @param cluster The cluster that we want to find a successor to.
 *
 * @return The (possibly newly allocated) cluster following the given
 * cluster in its cluster chain.  Returns zero if we needed a new
 * cluster and there was no free one.
 */
uint32_t fat_alloc_or_lookup(fat32_t *fat32, uint32_t cluster)
{
    uint32_t next = fat_lookup(fat32, cluster);

    KERNEL_ASSERT(cluster >= 2);

    if (next >= FAT32_MARK_EOC) {
        return fat_alloc(fat32, cluster);
    } else {
        return next;
    }
}

/**
 * Perform logical read from the disk, using FAT lookups to cross
 * cluster boundaries.
 *
 * @param buflen The number of bytes to read.
 *
 * @param target A buffer of at least buflen bytes to which the result will be written.
 *
 * @param cluster The number of the cluster at which reading will
 * begin.
 *
 * @param offset The offset (in bytes) into the given cluster at which
 * reading will begin.
 *
 * @return The number of bytes read.
 */
int read_from_disk(fat32_t *fat32, int buflen,
                   uint8_t *target, uint32_t cluster, int offset)
{
    int read = 0;
    int toread;
    int r;
    int inblock = 0;

    KERNEL_ASSERT(cluster >= 2);

    while (buflen > 0) {
        if (offset < FAT32_BLOCK_SIZE) {
            toread = MIN(buflen, FAT32_BLOCK_SIZE-offset);
            r = readblock(fat32, cluster_to_block(fat32, cluster)+inblock);
            if (r == 0) {
                return 0;
            }
            memcopy(toread, target+read, (void*)fat32->buffer_block+offset);
            read += toread;
            buflen -= toread;
            offset = 0;
        } else {
            offset -= FAT32_BLOCK_SIZE;
        }
        if (buflen != 0) {
            if (++inblock == fat32->volumeid.blocks_per_cluster) {
                cluster = fat_lookup(fat32, cluster);
                inblock = 0;
                if (cluster >= FAT32_MARK_EOC) {
                    break;
                }
            }
        }
    }
    return read;
}

/**
 * Perform logical write to the disk, using FAT lookups to cross
 * cluster boundaries and allocating new clusters if existing chain is
 * not large enough to hold the write.  Overwrites if writing in the
 * middle of a file.
 *
 * @param buflen The number of bytes to write.
 *
 * @param target A buffer of at least buflen bytes where the data to
 * write will be read from.
 *
 * @param cluster The number of the cluster at which writing will
 * begin.
 *
 * @param offset The offset (in bytes) into the given cluster at which
 * writing will begin.
 *
 * @return The number of bytes written.
 */
int write_to_disk(fat32_t *fat32, int buflen,
                  uint8_t *source, uint32_t cluster, int offset)
{
    int written = 0;
    int towrite;
    int r;
    int inblock = 0;
    while (buflen > 0) {
        if (offset < FAT32_BLOCK_SIZE) {
            towrite = MIN(buflen, FAT32_BLOCK_SIZE-offset);
            r = readblock(fat32, cluster_to_block(fat32, cluster)+inblock);
            if (r == 0) {
                return 0;
            }
            memcopy(towrite, (void*)fat32->buffer_block+offset, source+written);
            written += towrite;
            buflen -= towrite;
            offset = 0;
            r = writeblock(fat32, cluster_to_block(fat32, cluster)+inblock);
            if (r == 0) {
                return 0;
            }
        } else {
            offset -= FAT32_BLOCK_SIZE;
        }
        if (buflen != 0) {
            if (++inblock == fat32->volumeid.blocks_per_cluster) {
                cluster = fat_alloc_or_lookup(fat32, cluster);
                inblock = 0;
                if (cluster >= FAT32_MARK_EOC) {
                    break;
                }
            }
        }
    }
    return written;
}

int isalpha(int c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

int isdigit(int c)
{
    return (c >= '0' && c <= '9');
}

/**
 * Check whether the given character is valid in a short filename.
 */
int validshortchar(char c)
{
    switch (c) {
    case '$':
    case '%':
    case '\'':
    case '-':
    case '_':
    case '@':
    case '~':
    case '`':
    case '!':
    case '(':
    case ')':
    case '{':
    case '}':
    case '^':
    case '#':
    case '&':
        return 1;
    default:
        return isalpha(c) || isdigit(c);
    }
}

#define DATA_GET(type, block, idx) (*(type*)((block)+(idx)))

/**
 * Parse byte string as directly read from FAT32 file system as a
 * directory entry and write result to given struct.
 *
 * @param data Pointer to (at least) FAT32_ENTRY_SIZE bytes.
 *
 * @param entry Struct that will be filled with the result.
 */
int parse_directory_entry(uint8_t *data, dir_entry_t *entry)
{
    memcopy(11, entry->filename, data);
    entry->attributes = DATA_GET(int8_t, data, 0x0B);
    entry->first_cluster = l2b16(DATA_GET(int16_t, data, 0x14))<<8;
    entry->first_cluster += l2b16(DATA_GET(int16_t, data, 0x1A));
    entry->file_size = l2b32(DATA_GET(int32_t, data, 0x1C));
    return 0;
}

/**
 * Convert entry to a byte array suitable for immediate writing to
 * FAT32 file system.
 *
 * @param data Pointer to (at least) FAT32_ENTRY_SIZE bytes.
 *
 * @param entry The entry struct that will be converted to FAT32 disk
 * format.
 */
int write_directory_entry(uint8_t *dest, dir_entry_t *entry){
    memcopy(11, dest, entry->filename);
    DATA_GET(int8_t, dest, 0x0B) = entry->attributes;
    DATA_GET(int16_t, dest, 0x14) = b2l16(entry->first_cluster>>8);
    DATA_GET(int16_t, dest, 0x1A) = b2l16(entry->first_cluster & 0xFFFF);
    DATA_GET(int32_t, dest, 0x1C) = b2l32(entry->file_size);
    return 0;
}

/**
 * Read data from FAT32 header block.
 */
int parse_volumeid(uint8_t *block, fat32_volumeid_t *volumeid)
{
    volumeid->blocks_per_cluster = DATA_GET(int8_t, block, 0x0D);
    volumeid->reserved_blocks = l2b16(DATA_GET(int16_t, block, 0x0E));
    volumeid->blocks_per_fat = l2b32(DATA_GET(int32_t, block, 0x24));
    volumeid->root_first_cluster = l2b32(DATA_GET(int32_t, block, 0x2C));
    volumeid->total_blocks = l2b32(DATA_GET(int32_t, block, 0x20));
    return 0;
}

/**
 * Convert a FAT32 short filename (with space padding and all) into a
 * human-readable filename.
 *
 * @param dest Where the human-readable filename will be written.
 *
 * @param filename The FAT32 short filename read from the file system.
 */
void parse_short_filename(char* dest,
                          const char* filename)
{
    int i;
    for (i = 0; i < FAT32_VOLUMENAME_MAX; i++) {
        if (i == 8) {
            *dest++ = '.';
        }
        if (filename[i] != ' ') {
            *dest++ = filename[i];
        }
    }
    *dest = '\0';
}

typedef int (*entry_iterator)(file_identification_t*, void*);

/**
 * Iterate across the directory identified by the given cluster,
 * calling a supplied function for every real file found.
 *
 * @param cluster Number of the cluster where the directory starts.
 *
 * @param iterator For each file, this function is called with
 * information about the file and a user-supplied data pointer
 * (because C does not have closures).  If the iterator ever returns
 * zero, the iteration will stop.
 *
 * @param data A user-supplied pointer that will be passed to iterator.
 */
int iterate_directory(fat32_t *fat32, uint32_t cluster,
                      entry_iterator iterator, void* data)
{
    dir_entry_t entry;
    int proceed = 1;
    uint32_t read = 0;
    int r;
    uint8_t first_byte;
    file_identification_t ident;
    uint8_t namelen = 0;
    uint8_t entrydata[FAT32_ENTRY_SIZE];

    while (proceed != 0) {
        r = read_from_disk(fat32, FAT32_ENTRY_SIZE, entrydata, cluster, read*FAT32_ENTRY_SIZE);
        if(r == 0) {
            return VFS_ERROR;
        }
        parse_directory_entry(entrydata, &entry);
        first_byte = entrydata[0];
        if (first_byte == FAT32_ENTRY_END) {
            break;
        } else if (first_byte == FAT32_ENTRY_FREE) {
            /* Do nothing */
        } else if ((entry.attributes & ATTR_LONG_NAME_MASK) == ATTR_LONG_NAME) {
            /* Also do nothing. */
        } else {
            /* Copy the short record filename. */
            parse_short_filename(ident.filename, entry.filename);
            ident.attributes = entry.attributes;
            ident.first_cluster = entry.first_cluster;
            ident.file_size = entry.file_size;
            ident.short_entry_cluster = cluster;
            ident.short_entry_idx = read;
            proceed = (*iterator)(&ident, data);
            namelen = 0;
        }
        read++;
    }
    return 0;
}

/**
 * A function that can be given to iterate_directory for finding the
 * file containing the volume ID.
 */
int find_volumeid(file_identification_t *record, char* volumeid)
{
    if (record->attributes & ATTR_VOLUME_ID &&
        (record->attributes & ATTR_LONG_NAME_MASK) != ATTR_LONG_NAME) {
        int i, j;
        for (i = 0, j = 0; record->filename[i] != '\0'; i++) {
            if (record->filename[i] != '.') {
                volumeid[j++] = record->filename[i];
            }
        }
        return 0;
    } else {
        return 1;
    }
}

fs_t * fat32_init(gbd_t *disk) 
{
    uint32_t addr;
    gbd_request_t req;
    fs_t *fs;
    fat32_t *fat32;
    int r;
    semaphore_t *sem;
    fat32_volumeid_t volumeid;

    if(disk->block_size(disk) != FAT32_BLOCK_SIZE)
        return NULL;

    /* check semaphore availability before memory allocation */
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

    /* Assert that one page is enough */
    KERNEL_ASSERT(PAGE_SIZE >= (1*FAT32_BLOCK_SIZE+sizeof(fat32_t)+sizeof(fs_t)));
    
    /* Read header block, and make sure it contains FAT32 filesystem */
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

    if(((uint8_t *)addr)[510] != FAT32_MAGIC_1 ||
       ((uint8_t *)addr)[511] != FAT32_MAGIC_2) {
        semaphore_destroy(sem);
        pagepool_free_phys_page(ADDR_KERNEL_TO_PHYS(addr));
        return NULL;
    }

    parse_volumeid((uint8_t *)addr, &volumeid);

    /* fs_t, fat32_t and all buffers in fat32_t fit in one page, so
       obtain addresses for each structure and buffer inside the
       allocated memory page. */
    fs  = (fs_t *)addr;
    fat32 = (fat32_t *)(addr + sizeof(fs_t));
    fat32->disk        = disk;
    fat32->volumeid    = volumeid;
    fat32->hasblock    = 0;
    fat32->buffer_block = (uint8_t *)((uint32_t)fat32 + sizeof(fat32_t));
    fat32->fat_begin_block = 0 + fat32->volumeid.reserved_blocks;
    fat32->clusters_begin_block =
        0 + fat32->volumeid.reserved_blocks
        + (FAT32_NUMBER_OF_FATS * fat32->volumeid.blocks_per_fat);
    fat32->last_cluster = 
        (volumeid.total_blocks - fat32->clusters_begin_block) /
        volumeid.blocks_per_cluster;
    memoryset(fat32->open_files_table, 0x00, sizeof(open_file_t)*FAT32_MAX_OPEN_FILES);

    kprintf("FAT32 blocks per cluster: %u\n", fat32->volumeid.blocks_per_cluster);
    kprintf("FAT32 reserved blocks: %u\n", fat32->volumeid.reserved_blocks);
    kprintf("FAT32 blocks per FAT: %u\n", fat32->volumeid.blocks_per_fat);
    kprintf("FAT32 root first cluster: %u\n", fat32->volumeid.root_first_cluster);
    kprintf("FAT32 total blocks: %u\n", fat32->volumeid.total_blocks);
    kprintf("FAT32 last cluster: %u\n", fat32->last_cluster);

    /* save the semaphore to the fat32_t */
    fat32->lock = sem;

    fs->internal = (void *)fat32;
    /* Search for the volumeid-file. */
    if (iterate_directory(fat32, fat32->volumeid.root_first_cluster,
                          (entry_iterator)&find_volumeid, fs->volume_name) != 0) {
        return NULL;
    }

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


int fat32_unmount(fs_t *fs) {
    fs = fs;
    KERNEL_PANIC("to implement");
    return 0;
}

typedef struct {
    char *name;
    file_identification_t *result;
    uint8_t success;
} record_search_t;

int find_entry(file_identification_t *record, record_search_t *search)
{
    if (!(record->attributes & ATTR_VOLUME_ID) &&
        stringcmp((const char*)record->filename,
                  (const char*)search->name) == 0) {
        *(search->result) = *record;
        search->success = 1;
        return 0;
    } else {
        return 1;
    }
}

int check_if_open(fat32_t *fat32, uint32_t first_cluster)
{
    int found = FAT32_MAX_OPEN_FILES;
    int fd;
    for (fd = 0; fd < FAT32_MAX_OPEN_FILES; fd++) {
        if (fat32->open_files_table[fd].ident.short_entry_cluster == 0) {
            found = fd;
        } else if (fat32->open_files_table[fd].ident.first_cluster == first_cluster) {
            return fd;
        }
    }
    return found;
}

int fat32_open(fs_t *fs, char *filename)
{
    fs = fs; filename = filename;
    KERNEL_PANIC("to implement");
    return 0;
}

int fat32_close(fs_t *fs, int fileid)
{
    fs = fs; fileid = fileid;
    KERNEL_PANIC("to implement");
    return 0;
}

void make_short_name(char *dest, char *src)
{
    int i, j;
    for (i = j = 0; src[j] != '\0' && i < FAT32_VOLUMENAME_MAX; j++) {
        if (validshortchar(src[j])) {
            dest[i++] = src[j];
        }
    }
    for (; i < FAT32_VOLUMENAME_MAX; i++) {
        dest[i] = ' ';
    }
}

int32_t find_free_entry(fat32_t *fat32, uint32_t cluster)
{
    uint8_t entrydata[FAT32_ENTRY_SIZE];
    uint32_t i = 0;

    while (1) {
        read_from_disk(fat32, FAT32_ENTRY_SIZE, entrydata, cluster, i*FAT32_ENTRY_SIZE);
        if (entrydata[0] == FAT32_ENTRY_END) {
            break;
        } else if (entrydata[0] == FAT32_ENTRY_FREE) {
            return i;
        }
        i++;
    }
    return -1;
}

int fat32_create(fs_t *fs, char *filename, int size)
{
    fs = fs; filename = filename; size = size;
    KERNEL_PANIC("to implement");
    return 0;
}

int fat32_remove(fs_t *fs, char *filename) {
    fs = fs; filename = filename;
    KERNEL_PANIC("to implement");
    return 0;
}

int fat32_read(fs_t *fs, int fileid, void *buffer, int buflen, int offset)
{
    fs = fs; fileid = fileid; buffer = buffer; buflen = buflen; offset = offset;
    KERNEL_PANIC("to implement");
    return 0;
}

int fat32_write(fs_t *fs, int fileid, void *buffer, int datasize, int offset)
{
    fs = fs; fileid = fileid; buffer = buffer; datasize = datasize; offset = offset;
    KERNEL_PANIC("to implement");
    return 0;
}

int fat32_getfree(fs_t *fs) {
    fs = fs;
    KERNEL_PANIC("To implement");
    return 0;
}
