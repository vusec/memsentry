/*
 * Helper functions used by the MemSentry LLVM pass.
 * This code gets compiled into bitcode and compiled alongside the program, so
 * the pass can create calls to these and inline them. This saves us the effort
 * of writing the code to generate the corresponding IR.
 */

#include "internal.h"

/*****************************
 * SFI
 *****************************/
void *_memsentry_sfi(void *ptr) {
    return (void*)((uintptr_t)ptr & SFI_MASK);
}


/*****************************
 * MPX
 *****************************/
void *_memsentry_mpx(void *ptr) {
    __asm__ __volatile__ (
            "bndcu %0, %%bnd0 \n\t"
            :
            : "r" (ptr));
    return ptr;
}


/*****************************
 * VMFUNC
 *****************************/

void _memsentry_vmfunc_begin(void) {
    vmfunc_switch(VMFUNC_SECURE_DOMAIN);
}

void _memsentry_vmfunc_end(void) {
    vmfunc_switch(VMFUNC_NORMAL_DOMAIN);
}


/*****************************
 * MPK
 *****************************/
/* Simulate cost */
#define mpk_switch(mapping)                                                    \
	__asm__ __volatile__ (                                                     \
			"movq %%xmm14, %%r14 \n\t"                                         \
			"not %%r14 \n\t"                                                   \
			"movq %%r14, %%xmm14 \n\t"                                         \
            "mfence \n\t"                                                      \
			:::"%r14", "%xmm15");
void _memsentry_mpk_begin(void) {
    mpk_switch(1);
}

void _memsentry_mpk_end(void) {
    mpk_switch(0);
}


/*****************************
 * CRYPT
 *****************************/
void _memsentry_crypt_begin(void) {
    _memsentry_crypt_dec(_memsentry_crypt_area, _memsentry_max_region_size,
            _memsentry_crypt_iv);
}

void _memsentry_crypt_end(void) {
    _memsentry_crypt_enc(_memsentry_crypt_area, _memsentry_max_region_size,
            _memsentry_crypt_iv);
}
