#include <stdlib.h>
#include <stdio.h>

#include "internal.h"

/* Protection method used during compilation. Referenced from the runtime. */
enum prot_method  _memsentry_prot_method = -1;


/*****************************
 * MPX
 *****************************/
void _memsentry_mpx_init(void) {
    long lb=0, ub=MPX_UB;
    _memsentry_mpx_init_for_process();
    __asm__ __volatile__ (
            "bndmk (%0,%1), %%bnd0"
            :: "r"(lb), "r"(ub));
}

/*****************************
 * CRYPT
 *****************************/
void _memsentry_crypt_init(void) {
    _memsentry_crypt_checkcompat();
    _memsentry_crypt_init_keys();
    _memsentry_crypt_init_region();
}


__attribute__((constructor))
void _memsentry_init() {
    switch (_memsentry_prot_method) {
    case SFI:                              break;
    case MPX:    _memsentry_mpx_init();    break;
    case VMFUNC:                           break;
    case MPK:                              break;
    case CRYPT:  _memsentry_crypt_init();  break;
    default:
        fprintf(stderr, "Unknown protection method %d\n",
                _memsentry_prot_method);
        exit(1);
        break;
    }
}
