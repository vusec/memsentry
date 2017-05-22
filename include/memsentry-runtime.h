#ifndef MEMSENTRY_RUNTIME_H
#define MEMSENTRY_RUNTIME_H

#include <stdlib.h>

#ifndef SFI_MASK
/* 47 bits - allow entire userspace (works for benchmarking without modifying
 * address space).  */
//#define SFI_MASK 0x7fffffffffffULL
/* 46 bits - reserve 1 bit of the user address space, requires address space
 * layout modifications. */
#define SFI_MASK 0x3fffffffffffULL
#endif

#ifndef MPX_UB
#define MPX_UB SFI_MASK
#endif

void *_memsentry_alloc(size_t sz);

#define saferegion_alloc(sz) _memsentry_alloc(sz)

#endif /* MEMSENTRY_RUNTIME_H */
