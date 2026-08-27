/*
 * Fixture source for the r2.imports "plt 0 is not an address" live gate.
 *
 * A normal dynamically-linked ELF: gcc links it against libc, so radare2's
 * `iij` reports a mix of imports that resolve through the PLT (printf, strlen
 * -> plt != 0) and imports that do not (__libc_start_main and the weak
 * __gmon_start__ -> plt == 0, r2's sentinel for "no PLT stub"). That mix is
 * what the gate needs: the plt==0 imports must come back with no `address`,
 * while the real PLT stubs keep theirs.
 *
 * Rebuild (any glibc toolchain; exact addresses may differ, the gate does not
 * pin them, only that plt==0 and plt!=0 imports both exist):
 *   gcc -O0 -no-pie -o imports_sample imports_sample.c && strip imports_sample
 */
#include <stdio.h>
#include <string.h>

int add(int a, int b) { return a + b; }

int main(int argc, char **argv) {
    const char *s = "imports-sample-marker";
    printf("hello %s len=%zu\n", s, strlen(s));
    return add(argc, 3);
}
