/*
 * Allocate secure memory - per protection-method implementation.
 * Currently we assume a very simple allocation strategy: the defense allocates
 * some metadata that persists for the lifetime of the application. As such,
 * there is currently no support for freeing memory. Successive allocations are
 * supported.
 *
 * This limiated can easily be addressed by modifying the function in here to
 * keep, for instance, a freelist.
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>

#include "internal.h"


/* Used by some allocators to support successive allocations.
 * XXX: could pose security risk if allocations occur after attacker can corrupt
 *      this. */
static char *last_alloc = NULL;


static size_t _memsentry_pageround(size_t sz) {
    int pgz = sysconf(_SC_PAGESIZE);
    return (sz & ~(pgz - 1)) + pgz;
}

static void *_memsentry_generic_alloc_fromlast(size_t sz, void *start_addr) {
    if (!last_alloc)
        last_alloc = start_addr;
    fprintf(stderr, "doing alloc at %p of size %zu, start %p\n", last_alloc, sz, start_addr);
    sz = _memsentry_pageround(sz);
    if ((uintptr_t)last_alloc + sz >= 1ULL<<47) {
        fprintf(stderr, "ERROR: cannot allocate %zu bytes at %p, would exceed address-space limit.\n", sz, last_alloc);
        exit(1);
    }
    /* Note: this will trample over anything that may already be there. */
    char *pg = mmap(last_alloc, sz, PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (pg == MAP_FAILED) {
        perror("_memsentry_generic_alloc");
        return NULL;
    }
    last_alloc += sz;
    return pg;
}

/*****************************
 * SFI
 *****************************/

void *_memsentry_sfi_alloc(size_t sz) {
    return _memsentry_generic_alloc_fromlast(sz, (void*)(SFI_MASK+1+4096));
}


/*****************************
 * MPX
 *****************************/

void *_memsentry_mpx_alloc(size_t sz) {
    return _memsentry_generic_alloc_fromlast(sz, (void*)(MPX_UB+1+4096));
}


/*****************************
 * VMFUNC
 *****************************/

#define DUNE_VMCALL_SECRET_MAPPING_ADD 512

void *_memsentry_vmfunc_alloc(size_t sz) {
    void *pages;

    vmfunc_switch(VMFUNC_SECURE_DOMAIN);

    sz = _memsentry_pageround(sz);
    pages = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
            -1, 0);
    if (pages == MAP_FAILED)
    {
        perror("_memsentry_vmfunc_alloc");
        vmfunc_switch(VMFUNC_NORMAL_DOMAIN);
        return NULL;
    }
    syscall(DUNE_VMCALL_SECRET_MAPPING_ADD, pages, sz);

    vmfunc_switch(VMFUNC_NORMAL_DOMAIN);

    return pages;
}


/*****************************
 * MPK
 *****************************/

void *_memsentry_mpk_alloc(size_t sz) {
    void *pages;

    sz = _memsentry_pageround(sz);
    pages = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
            -1, 0);
    if (pages == MAP_FAILED)
    {
        perror("_memsentry_mpk_alloc");
        return NULL;
    }

    return pages;
}


/*****************************
 * CRYPT
 *****************************/

void *_memsentry_crypt_alloc(size_t sz) {
    char *ret;
    if (!last_alloc)
        last_alloc = _memsentry_crypt_area;
    if (last_alloc + sz > _memsentry_crypt_area + _memsentry_max_region_size) {
        fprintf(stderr, "ERROR: Allocation of %zu bytes at %p would exceed "
                "pre-allocated area at %p of %zu bytes\n", sz, last_alloc,
                _memsentry_crypt_area, _memsentry_max_region_size);
        exit(1);
    }
    ret = last_alloc;
    last_alloc += sz;
    return ret;
}



/*
 * Dispatch correct allocator
 */
void *_memsentry_alloc(size_t sz) {
    switch (_memsentry_prot_method) {
    case SFI:    return _memsentry_sfi_alloc(sz);
    case MPX:    return _memsentry_mpx_alloc(sz);
    case VMFUNC: return _memsentry_vmfunc_alloc(sz);
    case MPK:    return _memsentry_mpk_alloc(sz);
    case CRYPT:  return _memsentry_crypt_alloc(sz);
    default:
        fprintf(stderr, "Unknown protection method %d\n",
                _memsentry_prot_method);
        return NULL;
    }
}

