/*
 * Fixture source for the r2.xrefs "references to" live gate.
 *
 * Freestanding, non-PIE, statically linked so it depends on no libc and stays
 * tiny (~9 KiB) and reproducible. `helper` is deliberately called twice from
 * `_start` (r2 names it entry0) and `other` once, giving a known cross-
 * reference graph:
 *
 *   axtj @ sym.helper  -> exactly two CALL refs, both from entry0
 *   axj                -> the whole-binary xref table (helper's callers plus
 *                         every other ref in the file)
 *
 * so the gate can prove r2.xrefs now answers "who references helper?" with the
 * two callers (axtj), not the global dump (axj).
 *
 * Rebuild (radare2 5.x reports sym.helper at 0x401000):
 *   gcc -O0 -no-pie -nostdlib -static -o xref_sample xref_sample.c
 */
__attribute__((noinline)) int helper(int x) { return x * 3 + 1; }
__attribute__((noinline)) int other(int y) { return y - 7; }

void _start(void) {
    int a = helper(10);
    int b = helper(20);
    int c = other(a + b);
    __asm__ volatile("mov $60,%%eax; mov %0,%%edi; syscall" ::"r"(c) : "eax", "edi");
}
