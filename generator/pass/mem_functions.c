#include <stdlib.h>
#include <stdint.h>

/*
This file is assembled to LLVM IR (.ll) and later injected during compilation via
our custom LLVM-Pass.

We use the `always_inline` attrbiute to cause the compiler to generate a unique
patch point per per function call. Thus we have seperated mutation entries for
each (like semantically different) memory operation. Without inlineing, we would
have a huge mutation entry that we could only fuzz as one.
*/

/*
Custom memcpy implementation we can instrument.
*/
 __attribute__((always_inline))
void *custom_memcpy(void *restrict dst, const void *restrict src, size_t n) {
    size_t idx = 0;
    while (n--) {
        ((uint8_t*)dst)[idx] = ((uint8_t*)src)[idx];
        idx++;
    }
    return dst;
}

/*
Custom memmove implementation we can instrument.
! `restrict` is only valid as long the pointers do not point to the same
! memory location. We added this keyword because our custom memmove
! memmove implementation does a bytewise copy and is therefore not subjected
! to aliasing. If this is changed, these attrbiutes might need to be removed.
*/
 __attribute__((always_inline))
void *custom_memmove(void *restrict dst, const void *restrict src, size_t n) {
    size_t idx = 0;
    if (dst == src) {
        // ! This is a NOP and also not allowed as of `restrict`.
        return dst;
    }
    while (n--) {
        ((uint8_t*)dst)[idx] = ((uint8_t*)src)[idx];
        idx++;
    }
    return dst;
}