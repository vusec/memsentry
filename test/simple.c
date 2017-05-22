#include <stdio.h>
#include <stdlib.h>

#include "memsentry-runtime.h"


__attribute__ ((section("safe_functions"), noinline))
char safe_region_read(volatile char *ptr) {
    return *ptr;
}
__attribute__ ((section("safe_functions"), noinline))
void safe_region_write(volatile char *ptr, char v) {
    *ptr = v;
}

int main(int argc, char **argv) {
    volatile char *a = saferegion_alloc(10);
    volatile char *b = malloc(10);

    fprintf(stderr, "alloc: safe: %p  normal: %p\n", a, b);

    safe_region_write(a, 0x33);
    *b = 0x20; /* So the domain switches cannot be merged */
    char c = safe_region_read(a);
    fprintf(stderr, "Read %x from %p\n", c, a);

    fprintf(stderr, "The next line should not work (read from safe %p)\n", a);
    char invalid_read = *a;
    fprintf(stderr, "Read succeeded, value: %x (correct read: %x)\n",
            invalid_read, safe_region_read(a));
    return 0;
}
