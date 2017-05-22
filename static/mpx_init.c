/*
 *  Copyright (C) 2014, Intel Corporation
 *  All rights reserved.
 *
 *  @copyright
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *    * Neither the name of Intel Corporation nor the names of its
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 *  @copyright
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 *  AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
 *  WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Code to check for MPX compatibility and enabling.
 *
 * Taken from GCCs libmpx/mpxrt/mpxrt.c with minor modifications.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <cpuid.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#define REX_PREFIX      "0x48, "

#define bit_MPX	        (1 << 14)
#define bit_BNDREGS     (1 << 3)
#define bit_BNDCSR      (1 << 4)

/* x86_64 directory size is 2GB */
#define NUM_L1_BITS     28

#define REG_IP_IDX      REG_RIP
#define REX_PREFIX      "0x48, "

#define XSAVE_OFFSET_IN_FPMEM    0

#define MPX_ENABLE_BIT_NO  0
#define BNDPRESERVE_BIT_NO 1

const size_t MPX_L1_SIZE = (1UL << NUM_L1_BITS) * sizeof(void *);

struct xsave_hdr_struct {
    uint64_t xstate_bv;
    uint64_t reserved1[2];
    uint64_t reserved2[5];
} __attribute__ ((packed));

struct bndregs_struct {
    uint64_t bndregs[8];
} __attribute__ ((packed));

struct bndcsr_struct {
    uint64_t cfg_reg_u;
    uint64_t status_reg;
} __attribute__((packed));

struct xsave_struct {
    uint8_t fpu_sse[512];
    struct xsave_hdr_struct xsave_hdr;
    uint8_t ymm[256];
    uint8_t lwp[128];
    struct bndregs_struct bndregs;
    struct bndcsr_struct bndcsr;
} __attribute__ ((packed));

/* Following vars are initialized at process startup only
   and thus are considered to be thread safe.  */
static void *l1base = NULL;
static int bndpreserve = 1;
static int enable = 1;

static inline void _memsentry_xrstor_state(struct xsave_struct *fx,
        uint64_t mask) {
    uint32_t lmask = mask;
    uint32_t hmask = mask >> 32;

    __asm__ __volatile__ (
            ".byte " REX_PREFIX "0x0f,0xae,0x2f \n\t"
            :
            : "D" (fx), "m" (*fx), "a" (lmask), "d" (hmask)
            : "memory");
}

static void _memsentry_enable_mpx(void) {
    uint8_t __attribute__ ((__aligned__ (64))) buffer[4096];
    struct xsave_struct *xsave_buf = (struct xsave_struct *)buffer;

    memset(buffer, 0, sizeof(buffer));
    _memsentry_xrstor_state(xsave_buf, 0x18);

    fprintf(stderr, "Initalizing MPX...\n");
    fprintf(stderr, "  Enable bit: %d\n", enable);
    fprintf(stderr, "  BNDPRESERVE bit: %d\n", bndpreserve);

    /* Enable MPX.  */
    xsave_buf->xsave_hdr.xstate_bv = 0x10;
    xsave_buf->bndcsr.cfg_reg_u = (unsigned long)l1base;
    xsave_buf->bndcsr.cfg_reg_u |= enable << MPX_ENABLE_BIT_NO;
    xsave_buf->bndcsr.cfg_reg_u |= bndpreserve << BNDPRESERVE_BIT_NO;
    xsave_buf->bndcsr.status_reg = 0;

    _memsentry_xrstor_state(xsave_buf, 0x10);
}

static void _memsentry_disable_mpx(void) {
    uint8_t __attribute__ ((__aligned__ (64))) buffer[4096];
    struct xsave_struct *xsave_buf = (struct xsave_struct *)buffer;

    memset(buffer, 0, sizeof(buffer));
    _memsentry_xrstor_state(xsave_buf, 0x18);

    /* Disable MPX.  */
    xsave_buf->xsave_hdr.xstate_bv = 0x10;
    xsave_buf->bndcsr.cfg_reg_u = 0;
    xsave_buf->bndcsr.status_reg = 0;

    _memsentry_xrstor_state(xsave_buf, 0x10);
}

static bool _memsentry_check_mpx_support(void) {
    unsigned int eax, ebx, ecx, edx;
    unsigned int max_level = __get_cpuid_max(0, NULL);

    if (max_level < 13) {
        fprintf(stderr, "No required CPUID level support.\n");
        return false;
    }

    __cpuid_count(0, 0, eax, ebx, ecx, edx);
    if (!(ecx & bit_XSAVE)) {
        fprintf(stderr, "No XSAVE support.\n");
        return false;
    }

    if (!(ecx & bit_OSXSAVE)) {
        fprintf(stderr, "No OSXSAVE support.\n");
        return false;
    }

    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    if (!(ebx & bit_MPX)) {
        fprintf(stderr, "No MPX support.\n");
        return false;
    }

    __cpuid_count(13, 0, eax, ebx, ecx, edx);
    if (!(eax & bit_BNDREGS)) {
        fprintf(stderr, "No BNDREGS support.\n");
        return false;
    }

    if (!(eax & bit_BNDCSR)) {
        fprintf(stderr, "No BNDCSR support.\n");
        return false;
    }

    return true;
}

void _memsentry_mpx_init_for_process(void) {
    /* Check CPU support */
    if (!_memsentry_check_mpx_support()) {
        fprintf(stderr, "MPX not supported by CPU!\n");
        exit(EXIT_FAILURE);
    }

    l1base = mmap(NULL, MPX_L1_SIZE, PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
    if (l1base == MAP_FAILED) {
        perror("_memsentry_mpx_init_for_process");
        exit(EXIT_FAILURE);
    }

    _memsentry_enable_mpx();

    /* Check kernel support */
    if (prctl(43, 0, 0, 0, 0)) {
        fprintf(stderr, "MPX not supported by kernel!\n");
        _memsentry_disable_mpx();
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "MPX enabled!\n");
}

