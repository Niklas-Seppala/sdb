#include <fcntl.h> 
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h> 
#include <errno.h>
#include <assert.h>

#define PAGE_SIZE 4096
#define INITIAL_PAGE_COUNT 1
#define ERR_PAGE_ALLOC ((uint32_t)-1)

/**
 * Macro for the sizeof operator on stack value
 */
#define sdb_ssizeof(val) (sizeof(*(&val)))

typedef struct {
    int fd;
    void *mmapped;
    uint32_t page_count;
    size_t fsize;
} SDB;

#define RECOR_HEADER_SIZE 4

#define PAGE_META_OFFSET 0
#define PAGE_META 0x01
#define PAGE_LEAF 0x02
typedef struct {
    uint8_t type;        // META 0x01 | LEAF 0x02
    uint8_t flags;       // RESREVED
    uint16_t count;      // Number of entries
    uint32_t free_off;   // Offset to first free byte on the page
} __attribute__((packed)) SDBPageHeader;

typedef struct {
    SDBPageHeader haeder;
    uint32_t page_count;  // Total number of pages in the database
} __attribute__ ((packed)) SDBMetaPage;


static SDB *sdb_open(SDB *db, const char *filepath);
static void sdb_close(SDB *db);
static void *sdb_get_page(SDB *db, uint32_t page_num);
static uint32_t sdb_alloc_page(SDB *db);
static void init_meta_page(void *page_ptr, uint32_t initial_page_num);
static size_t leaf_record_space_required(uint16_t ksize, uint16_t vsize);
static void init_leaf_page(void *page);
static int sdb_leaf_insert(void *page, const void *key, uint16_t ksize, const void *val, uint16_t vsize);
static int sdb_leaf_scan(void *page);
static uint16_t *leaf_record_slot_array(void *page);

static void init_meta_page(void *page_ptr, uint32_t initial_page_num) {
    memset(page_ptr, 0, PAGE_SIZE);
    SDBMetaPage *meta_page = page_ptr;
    meta_page->haeder.type = PAGE_META;
    meta_page->haeder.flags = 0;
    meta_page->haeder.count = 0;
    meta_page->haeder.free_off = sizeof(SDBMetaPage);
    meta_page->page_count = initial_page_num;
}

size_t leaf_record_space_required(uint16_t ksize, uint16_t vsize) {
    return RECOR_HEADER_SIZE + ksize + vsize + sizeof(uint16_t);
}

static inline uint16_t *leaf_record_slot_array(void *page) {
    return (uint16_t *) ((uint8_t *)page + sizeof(SDBPageHeader));
}

// Record layout
//      [ key_size (2) | val_size (2) | key (ksize) | val (vsize) ]
//
int sdb_leaf_insert(void *page, const void *key, uint16_t ksize, const void *val, uint16_t vsize) {
    assert(page != NULL && "Page is null");
    assert(ksize > 0 && "key size is not valid");
    assert(vsize > 0 && "Value size is not valid");
    assert(key != NULL && "Key is null");
    assert(val != NULL && "Value is null");

    SDBPageHeader *header = page;

    if (header->type != PAGE_LEAF) {
        fprintf(stderr, "Attempt to write on non-leaf page\n");
        return - 1;
    }

    uint16_t count = header->count;
    size_t record_size = RECOR_HEADER_SIZE + ksize + vsize;
    size_t slot_size = sizeof(uint16_t);
    size_t slot_offset = sizeof(SDBPageHeader) + count * slot_size;

    if ((header->free_off + leaf_record_space_required(ksize, vsize)) > PAGE_SIZE) {
        return -2;
    }

    // TODO: refactor
    uint16_t current_end = (count == 0) ? PAGE_SIZE : ((uint16_t *)((uint8_t *)page + sizeof(SDBPageHeader)))[count - 1];
    uint16_t record_start = current_end - record_size;
    uint8_t *ptr = (uint8_t *)page + record_start;

    // Copy key & value sizes to record header.
    memcpy(ptr, &ksize, sdb_ssizeof(ksize));
    memcpy(ptr + sdb_ssizeof(ksize), &vsize, sdb_ssizeof(vsize));

    // Copy key to record.
    uint32_t key_offset = sdb_ssizeof(ksize) + sdb_ssizeof(vsize);
    memcpy(ptr + key_offset, key, ksize);

    // Copy value to record.
    uint32_t val_offset = key_offset + ksize;
    memcpy(ptr + val_offset, val, vsize);
    
    uint16_t *slots = leaf_record_slot_array(page);
    slots[count] = record_start;

    // Update header
    header->count++;
    header->free_off += slot_offset + slot_size;

    if (msync(page, PAGE_SIZE, MS_SYNC) < 0) {
        perror("msync");
        return -1;
    }

    return 0;
}


// Record layout
//      [ key_size (2) | val_size (2) | key (ksize) | val (vsize) ]
//
int sdb_leaf_scan(void *page) {
    assert(page != NULL && "page is null");

    SDBPageHeader *header = page;

    if (header->type != PAGE_LEAF) {
        fprintf(stderr, "Attempt to read on non-leaf page\n");
        return -1;
    }

    uint16_t count = header->count;
    uint16_t *slots = leaf_record_slot_array(page);

    for (uint16_t i = 0; i < count; i++) {
        uint16_t record_offset = slots[i];
        uint8_t *record = (uint8_t*)page + record_offset;
        
        // Read the key and value sizes
        uint16_t ksize = 0, vsize = 0;
        memcpy(&ksize, record, sdb_ssizeof(ksize));
        memcpy(&vsize, record + sdb_ssizeof(ksize), sdb_ssizeof(vsize));
        assert(ksize > 0 && "read key size is not valid");
        assert(vsize > 0 && "read value size is not valid");

        // Read the key.
        char key[ksize + 1];    //  (+1 for NULL, since we only work on string atm)
        const uint32_t key_offset = sdb_ssizeof(ksize) + sdb_ssizeof(vsize);
        memcpy(key, record + key_offset, ksize);
        key[ksize] = '\0';
        
        // Read the value.
        char val[vsize + 1];  //  (+1 for NULL, since we only work on string atm)
        const uint32_t val_offset = key_offset + ksize;
        memcpy(val, record + val_offset, vsize);
        val[vsize] = '\0';

        printf("Record %d: {key='%s', value='%s'}\n", i, key, val);
    }
}

void init_leaf_page(void *page) {
    memset(page, 0, PAGE_SIZE);
    SDBPageHeader *header = page;
    header->type = PAGE_LEAF;
    header->flags = 0;
    header->count = 0;
    header->free_off = sizeof(SDBPageHeader); 
}

SDB *sdb_open(SDB *db, const char *filepath) {
    if (db == NULL) {
        fprintf(stderr, "%s\n", "Null database ptr");
        return NULL;
    }

    db->fd = open(filepath, O_RDWR | O_CREAT, 0644);
    if (db->fd < 0) {
        perror("open()");
        return NULL;
    }

    struct stat st;
    if (fstat(db->fd, &st) < 0) {
        perror("fstat()");
        close(db->fd);
        exit(EXIT_FAILURE);
    }
    
    if (st.st_size == 0) {
        // New file
        db->fsize = PAGE_SIZE * INITIAL_PAGE_COUNT;
        if (ftruncate(db->fd, db->fsize) < 0) {
            perror("ftruncate()");;
            close(db->fd);
            return NULL;
        }
    } else {
        db->fsize = st.st_size;
    }

    db->mmapped = mmap(NULL, db->fsize, PROT_READ | PROT_WRITE, MAP_SHARED, db->fd, 0);
    if (db->mmapped == MAP_FAILED) {
        perror("mmap()");
        close(db->fd);
        return NULL;
    }

    SDBMetaPage *meta_page = sdb_get_page(db, PAGE_META_OFFSET);
    if (st.st_size == 0) {
        init_meta_page(meta_page, INITIAL_PAGE_COUNT);
        msync(db->mmapped, PAGE_SIZE, MS_SYNC);
    }
    db->page_count = meta_page->page_count;

    return db;
}

void sdb_close(SDB *db) {
    munmap(db->mmapped, db->fsize);
    close(db->fd);
}

void *sdb_get_page(SDB *db, uint32_t page_num) {
    if (page_num == PAGE_META_OFFSET) {
        return db->mmapped;
    }

    if(page_num >= db->page_count) {
        fprintf(stderr, "Page %u out of bounds: (max %u)\n", page_num, db->page_count - 1);
        return NULL;
    }

    size_t offset = page_num * PAGE_SIZE;
    return (void*) ((uint8_t *)db->mmapped + offset);
}

uint32_t sdb_alloc_page(SDB *db) {
    uint32_t new_page_num = db->page_count++;

    // Resize
    size_t new_size = db->page_count * PAGE_SIZE;
    if (ftruncate(db->fd, new_size) < 0) {
        perror("ftruncate()");
        return ERR_PAGE_ALLOC;
    }

    if (munmap(db->mmapped, db->fsize) < 0) {
        perror("munmap()");
        return ERR_PAGE_ALLOC;
    }

    db->fsize = new_size;
    db->mmapped = mmap(NULL, db->fsize, PROT_READ | PROT_WRITE, MAP_SHARED, db->fd, 0);
    if (db->mmapped == MAP_FAILED) {
        perror("mmap()");
        return ERR_PAGE_ALLOC;
    }

    // Update metadata
    SDBMetaPage *meta = sdb_get_page(db, PAGE_META_OFFSET);
    if (meta) {
        meta->page_count = db->page_count;
        msync(meta, PAGE_SIZE, MS_SYNC);
    }

    return new_page_num;
}

int main(int argc, char const *argv[]) {
    SDB db = {0};

    if (!sdb_open(&db, "file.db")) {
        fprintf(stderr, "Failed to open db\n");
    }
    
    uint32_t page = sdb_alloc_page(&db);
    if (page != ERR_PAGE_ALLOC) {
        void *page_ptr = sdb_get_page(&db, page);
        init_leaf_page(page_ptr);

        const char *key = "name";
        const char *val1 = "Jenni";
        const char *val2 = "Niklas";
        sdb_leaf_insert(page_ptr, key, strlen(key), val1, strlen(val1));
        sdb_leaf_insert(page_ptr, key, strlen(key), val2, strlen(val2));
    }

    for (uint32_t i = 1; i < db.page_count; i++) {
        void *page = sdb_get_page(&db, i);
        sdb_leaf_scan(page);
    }

    sdb_close(&db);
    return 0;
}
