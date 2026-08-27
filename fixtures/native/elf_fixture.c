/* Harmless portable fixture for Linux x86_64 static-analysis gates.
 *
 * The repository ships C sources, not binaries, so this is compiled at test
 * time (see the `elf_fixture` pytest fixture in tests/integration/conftest.py)
 * and every architecture builds its own. The named helper and its caller give
 * radare2/rizin (and any future Ghidra Linux gate) real functions with a
 * cross-reference to find and map to addresses. It does nothing but arithmetic
 * and one print, so it is safe to analyse anywhere. */
#include <stdio.h>

int elf_fixture_transform(int value) {
    int acc = value;
    for (int i = 0; i < 4; i++) {
        acc = acc * 3 + 1;
    }
    return acc & 0x7fffffff;
}

int main(void) {
    int result = elf_fixture_transform(7);
    printf("elf-fixture:%d\n", result);
    return result & 0xff;
}
