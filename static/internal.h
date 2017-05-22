#ifndef MEMSENTRY_STATIC_INTERNAL_H
#define MEMSENTRY_STATIC_INTERNAL_H

#include "memsentry-runtime.h"
#include "types.h"

extern enum prot_method _memsentry_prot_method;

/* mpx_init.c */
void _memsentry_mpx_init_for_process(void);

/* crypt.c */
void _memsentry_crypt_checkcompat(void);
void _memsentry_crypt_init_region(void);
void _memsentry_crypt_init_keys(void);
void _memsentry_crypt_enc(char *data, size_t len, char *iv);
void _memsentry_crypt_dec(char *data, size_t len, char *iv);

extern size_t _memsentry_max_region_size;
extern char *_memsentry_crypt_area;
extern char *_memsentry_crypt_iv;

#define VMFUNC_NORMAL_DOMAIN 0
#define VMFUNC_SECURE_DOMAIN 1

#define vmfunc_switch(mapping)                                                 \
    __asm__ __volatile__ (                                                     \
            "mov $0, %%eax \n\t" /* vmfunc number (0=eptp switch) */           \
            "mov %0, %%ecx \n\t" /* eptp index */                              \
            "vmfunc \n\t"                                                      \
            :                                                                  \
            : "irm"(mapping)                                                   \
            : "%rax", "%rcx", "memory");

#endif /* MEMSENTRY_STATIC_INTERNAL_H */
