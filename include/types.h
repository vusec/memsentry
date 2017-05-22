/*
 * Types shared between passes and static library.
 */

#ifndef MEMSENTRY_TYPES_H
#define MEMSENTRY_TYPES_H

#include <stdint.h>

enum readwrite {
    READ,
    WRITE,
    READWRITE,
};

enum prot_method {
    SFI = 0,
    MPX,
    VMFUNC,
    MPK,
    CRYPT,
};

#ifdef __cplusplus
static std::string prot_method_strings[] = {
    "sfi",
    "mpx",
    "vmfunc",
    "mpk",
    "crypt",
};
#endif


#endif /* MEMSENTRY_TYPES_H */

