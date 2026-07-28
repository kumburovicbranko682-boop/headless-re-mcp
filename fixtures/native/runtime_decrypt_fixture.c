/* Harmless DLL: decrypts an in-memory blob then raises a visible flag. */
#include <windows.h>

static unsigned char g_blob[16] = {
    /* plaintext "HEADLESS-RE-FLAG" XOR 0x5A */
    0x12, 0x1F, 0x1B, 0x1E, 0x16, 0x1F, 0x09, 0x09,
    0x07, 0x77, 0x08, 0x1F, 0x1C, 0x16, 0x1B, 0x1D
};
static volatile LONG g_flag = 0;

__declspec(dllexport) DWORD WINAPI runtime_decrypt_trigger(void)
{
    SIZE_T i;
    for(i = 0; i < sizeof(g_blob); ++i)
        g_blob[i] ^= 0x5A;
    InterlockedExchange(&g_flag, 0x48445246UL); /* 'HDRF' */
    return (DWORD)g_flag;
}

__declspec(dllexport) DWORD WINAPI runtime_decrypt_flag(void)
{
    return (DWORD)g_flag;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
