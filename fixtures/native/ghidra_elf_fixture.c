/* Source for ghidra_elf_fixture, the Linux ELF the Ghidra gate analyses.
 *
 * Rebuild it (not stripped, non-PIE so entry points are stable) with:
 *
 *   gcc -O0 -fno-pic -no-pie -fno-stack-protector \
 *       -o fixtures/native/ghidra_elf_fixture fixtures/native/ghidra_elf_fixture.c
 *
 * It gives Ghidra headless something real to recover: named functions
 * (compute_checksum, greet, main) for the functions/symbols export, a call
 * edge from main into compute_checksum for xrefs, and a small body that
 * decompiles back to readable C.
 */
#include <stdio.h>

int compute_checksum(const char *text) {
    int sum = 0;
    for (const char *cursor = text; *cursor != '\0'; ++cursor) {
        sum = (sum * 31) + (unsigned char)*cursor;
    }
    return sum;
}

void greet(const char *who) {
    printf("hello %s\n", who);
}

int main(void) {
    const char *marker = "headless-re ghidra gate fixture";
    greet(marker);
    return compute_checksum(marker);
}
