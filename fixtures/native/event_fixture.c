#include <windows.h>

__declspec(dllexport) __declspec(noinline) DWORD WINAPI event_fixture_one_shot_value(void)
{
    return 0x48524531UL;
}

__declspec(dllexport) __declspec(noinline) DWORD WINAPI event_fixture_persistent_value(void)
{
    return 0x48524532UL;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}