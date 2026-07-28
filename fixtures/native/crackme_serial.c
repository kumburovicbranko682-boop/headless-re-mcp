#include <stdio.h>
#include <string.h>
__declspec(dllexport) int __cdecl crackme_check(const char *serial) {
    static const unsigned char expect[] = {0x09,0x72,0x20,0x25,0x2d,0x72,0x32,0x32};
    unsigned char buf[16]={0};
    size_t n, i;
    if(!serial) return 0;
    n = strlen(serial);
    if(n != 8) return 0;
    for(i=0;i<n;i++) buf[i] = (unsigned char)serial[i] ^ 0x41;
    return memcmp(buf, expect, 8) == 0;
}
int main(int argc, char **argv) {
    char line[64]={0};
    if(argc >= 2) {
        if(crackme_check(argv[1])) { puts("OK"); return 0; }
        puts("FAIL"); return 1;
    }
    fputs("serial> ", stdout); fflush(stdout);
    if(!fgets(line, sizeof line, stdin)) return 2;
    line[strcspn(line, "\r\n")] = 0;
    if(crackme_check(line)) { puts("OK"); return 0; }
    puts("FAIL"); return 1;
}
