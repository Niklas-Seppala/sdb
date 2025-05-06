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

#define PAGE_SIZE 4096
#define INITIAL_PAGE_COUNT 1
#define ERR_PAGE_ALLOC ((uint32_t)-1)

typedef struct {
    int fd;
    void *mmapped;
    uint32_t page_count;
    size_t fsize;
} SDB;

#define PAGE_META_OFFSET 0
#define PAGE_META 0x01
#define PAGE_LEAF 0x02
typedef struct {
    uint8_t type;        // META 0x01 | LEAF 0x02
    uint8_t flags;       // RESREVED
    uint16_t count;      // Number of entries
    uint32_t free_off;   // Offset to first free byte on the page
} __attribute__((packed)) SDBPageHeader;


static SDB *sdb_open(SDB *db, const char *filepath);
static void sdb_close(SDB *db);
static void *sdb_get_page(SDB *db, uint32_t page_num);
static uint32_t sdb_alloc_page(SDB *db);
static void init_meta_page(void *page_ptr, uint32_t initial_page_num);
static void init_leaf_page(void *page);

typedef struct {
    SDBPageHeader haeder;
    uint32_t page_count;  // Total number of pages in the database
} __attribute__ ((packed)) SDBMetaPage;

static void init_meta_page(void *page_ptr, uint32_t initial_page_num) {
    memset(page_ptr, 0, PAGE_SIZE);
    SDBMetaPage *meta_page = page_ptr;
    meta_page->haeder.type = PAGE_META;
    meta_page->haeder.flags = 0;
    meta_page->haeder.count = 0;
    meta_page->haeder.free_off = sizeof(SDBMetaPage);
    meta_page->page_count = initial_page_num;
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
    close(db->fd);
}

void *sdb_get_page(SDB *db, uint32_t page_num) {
    if (page_num == 0) {
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

    db->mmapped = mmap(NULL, db->fsize, PROT_READ | PROT_WRITE, MAP_SHARED, db->fd, 0);
    if (db->mmapped == MAP_FAILED) {
        perror("mmap()");
        return ERR_PAGE_ALLOC;
    }

    db->fsize = new_size;

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
    }

    sdb_close(&db);
    return 0;
}
