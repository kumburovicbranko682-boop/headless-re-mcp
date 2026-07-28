/* Harmless PE with a fixed, documented import set for M4.5 IAT tests. */
#include <windows.h>
#include <stdint.h>

#pragma comment(lib, "kernel32.lib")

__declspec(noinline) uintptr_t predictable_imports_touch(void)
{
    /* Actually call imports so MSVC cannot strip the IAT entries. */
    HMODULE kernel = GetModuleHandleA("kernel32.dll");
    FARPROC proc = GetProcAddress(kernel, "VirtualAlloc");
    LPVOID page = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD old_protect = 0;
    BOOL ok = FALSE;
    if(page != NULL)
        ok = VirtualProtect(page, 4096, PAGE_READONLY, &old_protect);
    HMODULE again = LoadLibraryA("kernel32.dll");
    uintptr_t marker = (uintptr_t)kernel ^ (uintptr_t)proc ^ (uintptr_t)page
        ^ (uintptr_t)ok ^ (uintptr_t)again;
    if(again != NULL)
        FreeLibrary(again);
    if(page != NULL)
        VirtualFree(page, 0, MEM_RELEASE);
    return marker;
}

int main(void)
{
    volatile uintptr_t marker = predictable_imports_touch();
    (void)marker;
    return 0;
}
