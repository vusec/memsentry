#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <cpuid.h>
#include <immintrin.h>
#include <sys/mman.h>

/* XMM/YMM registers to use */
/* For permanently storing all round-keys. */
#define K0 "5"
#define K1 "6"
#define K2 "7"
#define K3 "8"
#define K4 "9"
#define K5 "10"
#define K6 "11"
#define K7 "12"
#define K8 "13"
#define K9 "14"
#define K10 "15"
/* For enc/dec (contains value to work on) */
#define XMM_SCRATCH "4"
/* Decryption key (temp) */
#define DK "3"
/* For inserting xmm into ymm without loss of lower-half ymm */
#define YMM_SCRATCH "2"

/* XMM instructions */
#define XMM_LOAD(xmm_n, l, h) \
    __asm__ __volatile__ ( \
            "pinsrq $0, %0, %%xmm" xmm_n " \n\t" \
            "pinsrq $1, %1, %%xmm" xmm_n " \n\t" \
            : \
            : "r"((uint64_t)l), "r"((uint64_t)h) \
            : "xmm" xmm_n);
#define XMM_TO_VAR64(xmm_n, l, h) \
    __asm__ __volatile__ ( \
            "pinsrq $0, %0, %%xmm" xmm_n " \n\t" \
            "pinsrq $1, %1, %%xmm" xmm_n " \n\t" \
            : \
            : "r"((uint64_t)l), "r"((uint64_t)h) \
            : "xmm" xmm_n);
#define XMM_TO_VAR(xmm_n, v) \
    __asm__ __volatile__ ( \
            "movdqa %%xmm" xmm_n ", %0 \n\t" \
            : "=x"(v) \
            : \
            : "xmm" xmm_n);
#define XMM_FROM_VAR(xmm_n, v) \
    __asm__ __volatile__ ( \
            "movdqa %0, %%xmm" xmm_n " \n\t" \
            : \
            : "x"(v) \
            : "xmm" xmm_n);
#define XMM_XOR(xmm_v, xmm_k) \
    __asm__ __volatile__ ( \
            "xorps %%xmm" xmm_k ", %%xmm" xmm_v " \n\t" \
            : \
            : \
            : "xmm" xmm_v, "xmm" xmm_k);
#define XMM_TO_XMM(xmm_n, xmm_m) \
    __asm__ __volatile__ ( \
            "movdqa %%xmm" xmm_n ", %%xmm" xmm_m " \n\t" \
            : \
            : \
            : "xmm" xmm_n, "xmm" xmm_m);

/* YMM instructions */
#define YMM_UPPER_FROM_XMM(ymm_n, xmm_n) \
    __asm__ __volatile__ (\
            "vmovdqa %%ymm" ymm_n ", %%ymm" YMM_SCRATCH " \n\t" \
            "vinserti128 $1, %%xmm" xmm_n ", %%ymm" YMM_SCRATCH ", %%ymm" ymm_n " \n\t" \
            : \
            : \
            : "xmm" xmm_n, "ymm" ymm_n, "ymm" YMM_SCRATCH);
#define YMM_UPPER_TO_XMM(ymm_n, xmm_n) \
    __asm__ __volatile__ (\
            "vextracti128 $1, %%ymm" ymm_n ", %%xmm" xmm_n " \n\t" \
            : \
            : \
            : "xmm" xmm_n, "ymm" ymm_n);


/* AES instruction */
#define AES_ENC(xmm_v, xmm_k) \
    __asm__ __volatile__ ( \
            "aesenc %%xmm" xmm_k ", %%xmm" xmm_v " \n\t" \
            : \
            : \
            : "xmm" xmm_v, "xmm" xmm_k);
#define AES_ENCLAST(xmm_v, xmm_k) \
    __asm__ __volatile__ ( \
            "aesenclast %%xmm" xmm_k ", %%xmm" xmm_v " \n\t" \
            : \
            : \
            : "xmm" xmm_v, "xmm" xmm_k);
#define AES_IMC(xmm_k, xmm_dk) \
    __asm__ __volatile__ ( \
            "aesimc %%xmm" xmm_k ", %%xmm" xmm_dk " \n\t" \
            : \
            : \
            : "xmm" xmm_k, "xmm" xmm_dk);
#define AES_DEC(xmm_v, xmm_dk) \
    __asm__ __volatile__ ( \
            "aesdec %%xmm" xmm_dk ", %%xmm" xmm_v " \n\t" \
            : \
            : \
            : "xmm" xmm_v, "xmm" xmm_dk);
#define AES_DECLAST(xmm_v, xmm_dk) \
    __asm__ __volatile__ ( \
            "aesdeclast %%xmm" xmm_dk ", %%xmm" xmm_v " \n\t" \
            : \
            : \
            : "xmm" xmm_v, "xmm" xmm_dk);

#define AES_KEYEXP(xmm_prev, xmm_new, xmm_tmp, rcon) \
    __asm__ __volatile__ ( \
            "movdqa %%xmm" xmm_prev ", %%xmm" xmm_tmp " \n\t" \
            "movdqa %%xmm" xmm_prev ", %%xmm" xmm_new " \n\t" \
            "pslldq $4, %%xmm" xmm_tmp " \n\t" \
            "pxor %%xmm" xmm_tmp ", %%xmm" xmm_new " \n\t" \
            "pslldq $4, %%xmm" xmm_tmp " \n\t" \
            "pxor %%xmm" xmm_tmp ", %%xmm" xmm_new " \n\t" \
            "pslldq $4, %%xmm" xmm_tmp " \n\t" \
            "pxor %%xmm" xmm_tmp ", %%xmm" xmm_new " \n\t" \
            "aeskeygenassist $" #rcon ", %%xmm" xmm_prev ", %%xmm" xmm_tmp " \n\t" \
            "pshufd $255, %%xmm" xmm_tmp ", %%xmm" xmm_tmp " \n\t" \
            "pxor %%xmm" xmm_tmp ", %%xmm" xmm_new " \n\t" \
            : \
            : \
            : "xmm" xmm_prev, "xmm" xmm_new, "xmm" xmm_tmp);

#define AES_KEYGEN_ALL_YMM(xmm_k) \
    XMM_TO_XMM(xmm_k, K0); \
    YMM_UPPER_FROM_XMM(K0, K0); \
    AES_KEYEXP(K0, K1, XMM_SCRATCH, 0x01); \
    YMM_UPPER_FROM_XMM(K1, K1); \
    AES_KEYEXP(K1, K2, XMM_SCRATCH, 0x02); \
    YMM_UPPER_FROM_XMM(K2, K2); \
    AES_KEYEXP(K2, K3, XMM_SCRATCH, 0x04); \
    YMM_UPPER_FROM_XMM(K3, K3); \
    AES_KEYEXP(K3, K4, XMM_SCRATCH, 0x08); \
    YMM_UPPER_FROM_XMM(K4, K4); \
    AES_KEYEXP(K4, K5, XMM_SCRATCH, 0x10); \
    YMM_UPPER_FROM_XMM(K5, K5); \
    AES_KEYEXP(K5, K6, XMM_SCRATCH, 0x20); \
    YMM_UPPER_FROM_XMM(K6, K6); \
    AES_KEYEXP(K6, K7, XMM_SCRATCH, 0x40); \
    YMM_UPPER_FROM_XMM(K7, K7); \
    AES_KEYEXP(K7, K8, XMM_SCRATCH, 0x80); \
    YMM_UPPER_FROM_XMM(K8, K8); \
    AES_KEYEXP(K8, K9, XMM_SCRATCH, 0x1B); \
    YMM_UPPER_FROM_XMM(K9, K9); \
    AES_KEYEXP(K9, K10, XMM_SCRATCH, 0x36); \
    YMM_UPPER_FROM_XMM(K10, K10);

#define AES_ENCROUNDS_YMMRK(xmm_v) \
    YMM_UPPER_TO_XMM(K0, DK); \
    XMM_XOR(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K1, DK); \
    AES_ENC(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K2, DK); \
    AES_ENC(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K3, DK); \
    AES_ENC(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K4, DK); \
    AES_ENC(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K5, DK); \
    AES_ENC(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K6, DK); \
    AES_ENC(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K7, DK); \
    AES_ENC(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K8, DK); \
    AES_ENC(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K9, DK); \
    AES_ENC(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K10, DK); \
    AES_ENCLAST(xmm_v, DK);

#define AES_DECROUNDS_YMMRK(xmm_v) \
    YMM_UPPER_TO_XMM(K10, DK); \
    /* No IMC for K10 */ \
    XMM_XOR(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K9, DK); \
    AES_IMC(DK, DK); \
    AES_DEC(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K8, DK); \
    AES_IMC(DK, DK); \
    AES_DEC(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K7, DK); \
    AES_IMC(DK, DK); \
    AES_DEC(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K6, DK); \
    AES_IMC(DK, DK); \
    AES_DEC(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K5, DK); \
    AES_IMC(DK, DK); \
    AES_DEC(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K4, DK); \
    AES_IMC(DK, DK); \
    AES_DEC(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K3, DK); \
    AES_IMC(DK, DK); \
    AES_DEC(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K2, DK); \
    AES_IMC(DK, DK); \
    AES_DEC(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K1, DK); \
    AES_IMC(DK, DK); \
    AES_DEC(xmm_v, DK); \
    YMM_UPPER_TO_XMM(K0, DK); \
    /* No IMC for K0 */ \
    AES_DECLAST(xmm_v, DK);


/* Area we will encrypt. XXX: make sure attacker cannot corrupt (store in ymm
 * or so). */
size_t _memsentry_max_region_size = -1;
char *_memsentry_crypt_area = (char*)-1;
char *_memsentry_crypt_iv = (char*)-1;


/* Performs full CBC AES-128 encryption on a given area. Assumes the round keys
 * are in the upper parts of the ymm registers. */
void _memsentry_crypt_enc(char *data, size_t len, char *iv) {
    __m128i prevblock, tmp;
    size_t i;

    /* Use IV for first iteration of CBC instead of previous block. */
    prevblock = _mm_load_si128((void*)iv);

    for (i = 0; i < len / 16; i++) {
        tmp = _mm_load_si128((void*)data);
        tmp = _mm_xor_si128(tmp, prevblock);
        XMM_FROM_VAR(XMM_SCRATCH, tmp);
        AES_ENCROUNDS_YMMRK(XMM_SCRATCH);
        XMM_TO_VAR(XMM_SCRATCH, prevblock);
        _mm_store_si128((void*)data, prevblock);
        data += 16;
    }
}

/* Performs full CBC AES-128 decryption on a given area. Assumes the round keys
 * are in the upper parts of the ymm registers. */
void _memsentry_crypt_dec(char *data, size_t len, char *iv) {
    __m128i prevblock, tmp, prevblock_crypt;
    size_t i;

    /* Use IV for first iteration of CBC instead of previous block. */
    prevblock = _mm_load_si128((void*)iv);

    for (i = 0; i < len / 16; i++) {
        /* Save ciphertext as we need it next round for XOR. */
        prevblock_crypt = _mm_load_si128((void*)data);
        XMM_FROM_VAR(XMM_SCRATCH, prevblock_crypt);
        AES_DECROUNDS_YMMRK(XMM_SCRATCH);
        XMM_TO_VAR(XMM_SCRATCH, tmp);
        tmp = _mm_xor_si128(tmp, prevblock);
        prevblock = prevblock_crypt;
        _mm_store_si128((void*)data, tmp);
        data += 16;
    }
}

void _memsentry_crypt_checkcompat(void) {
    unsigned a, b, c, d;

    __cpuid(1, a, b, c, d);
    if (!(c & 0x2000000))  {
        fprintf(stderr, "CPU does not support AES-NI extensions");
        exit(EXIT_FAILURE);
    }
    __cpuid_count(7, 0, a, b, c, d);
    if (!(b & (1 << 5))) {
        fprintf(stderr, "CPU does not support AVX2 extensions");
        exit(EXIT_FAILURE);
    }
}

void _memsentry_crypt_init_keys(void) {
    /* Load a random key into the upper part of an YMM register, which should
     * never be touched by the normal application. */

    /* TODO random */
    XMM_LOAD(XMM_SCRATCH, 0x0706050403020100, 0x0f0e0d0c0b0a0908);
    AES_KEYGEN_ALL_YMM(XMM_SCRATCH);
}

void _memsentry_crypt_init_region(void) {
    unsigned i;

    assert((_memsentry_max_region_size % 4096) == 0);

    _memsentry_crypt_area = mmap(NULL, _memsentry_max_region_size,
            PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

    /* CBC needs an IV */
    _memsentry_crypt_iv = malloc(16);
    for (i = 0; i < 16; i++)
        _memsentry_crypt_iv[i] = i | (i << 4);

    /* Fill area with some data for debugging */
    for (i = 0; i < _memsentry_max_region_size; i++)
        _memsentry_crypt_area[i] = i % 256;


    /* Start the area off as encrypted until a domain needs it */
    _memsentry_crypt_enc(_memsentry_crypt_area, _memsentry_max_region_size,
            _memsentry_crypt_iv);
}

