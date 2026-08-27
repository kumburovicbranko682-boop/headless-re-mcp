/* Source for r2_elf_fixture, the Linux ELF the radare2 gate reads.
 *
 * Rebuild it (not stripped, non-PIE so addresses are stable) with:
 *
 *   gcc -O0 -fno-pic -no-pie -fno-stack-protector \
 *       -o fixtures/native/r2_elf_fixture fixtures/native/r2_elf_fixture.c
 *
 * It exists so the r2.* surface has something real to parse on Linux: two
 * named functions (main, compute_checksum) for aflj to list and disassemble,
 * a marker string in .rodata for izj to find, and a libc import (printf) for
 * iij. radare2 handles ELF natively, so the gate needs no Windows fixture.
 */
#include <stdio.h>

static const char MARKER[] = "headless-re radare2 gate fixture";

int compute_checksum(const char *text) {
    int sum = 0;
    for (const char *cursor = text; *cursor != '\0'; ++cursor) {
        sum = (sum * 31) + (unsigned char)*cursor;
    }
    return sum;
}

int main(void) {
    printf("%s\n", MARKER);
    printf("checksum=%d\n", compute_checksum(MARKER));
    return 0;
}
