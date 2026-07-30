#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

__declspec(noinline) uint64_t fixture_marker(uint64_t left, uint64_t right)
{
    volatile uint64_t value = (left ^ 0x484541444C455353ULL) + right;
    return value;
}

static DWORD WINAPI fixture_thread(LPVOID parameter)
{
    volatile LONG* counter = (volatile LONG*)parameter;
    InterlockedIncrement(counter);
    return 0;
}

static int run_threads(unsigned count, volatile LONG* counter)
{
    unsigned index;
    for(index = 0; index < count; ++index)
    {
        HANDLE thread = CreateThread(NULL, 0, fixture_thread, (LPVOID)counter, 0, NULL);
        if(thread == NULL)
            return 2;
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
    }
    return 0;
}

static int load_event_module(HMODULE* loaded)
{
    wchar_t path[MAX_PATH];
    wchar_t* separator;
    DWORD length = GetModuleFileNameW(NULL, path, MAX_PATH);
    if(length == 0 || length >= MAX_PATH)
        return 4;
    separator = wcsrchr(path, L'\\');
    if(separator == NULL)
        return 4;
    separator[1] = L'\0';
    if(wcslen(path) + wcslen(L"event_fixture.dll") >= MAX_PATH)
        return 4;
    wcscat(path, L"event_fixture.dll");

    *loaded = LoadLibraryW(path);
    return *loaded == NULL ? 5 : 0;
}

typedef DWORD(WINAPI* event_fixture_function)(void);

static FARPROC resolve_event_export(HMODULE module, const char* name)
{
    FARPROC address = GetProcAddress(module, name);
#if defined(_M_IX86) || defined(__i386__)
    char decorated[128];
    int written;
    if(address != NULL)
        return address;
#ifdef _MSC_VER
    written = sprintf_s(decorated, sizeof(decorated), "_%s@0", name);
#else
    written = snprintf(decorated, sizeof(decorated), "_%s@0", name);
#endif
    if(written > 0 && (size_t)written < sizeof(decorated))
        address = GetProcAddress(module, decorated);
    if(address != NULL)
        return address;
#ifdef _MSC_VER
    written = sprintf_s(decorated, sizeof(decorated), "%s@0", name);
#else
    written = snprintf(decorated, sizeof(decorated), "%s@0", name);
#endif
    if(written > 0 && (size_t)written < sizeof(decorated))
        address = GetProcAddress(module, decorated);
#endif
    return address;
}

static int invoke_event_export(HMODULE module, const char* name, DWORD expected)
{
    FARPROC raw = resolve_event_export(module, name);
    event_fixture_function function;
    if(raw == NULL)
        return 10;
    function = (event_fixture_function)raw;
    return function() == expected ? 0 : 11;
}

static SIZE_T event_module_image_size(HMODULE module)
{
    const BYTE* base = (const BYTE*)module;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)base;
    const IMAGE_NT_HEADERS* nt;
    if(dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
        return 0;
    nt = (const IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if(nt->Signature != IMAGE_NT_SIGNATURE)
        return 0;
    return (SIZE_T)nt->OptionalHeader.SizeOfImage;
}

static int run_workflow_module_reload(void)
{
    HMODULE first = NULL;
    HMODULE second = NULL;
    LPVOID old_base;
    LPVOID blocker = NULL;
    SIZE_T image_size;
    int status = load_event_module(&first);
    if(status != 0)
        return status;
    old_base = (LPVOID)first;
    image_size = event_module_image_size(first);
    if(image_size == 0)
        return 12;

    Sleep(3000);
    status = invoke_event_export(
        first, "event_fixture_one_shot_value", 0x48524531UL);
    if(status != 0)
        return status;
    Sleep(3000);
    if(!FreeLibrary(first))
        return 7;
    first = NULL;

    Sleep(3000);
    blocker = VirtualAlloc(
        old_base, image_size, MEM_RESERVE, PAGE_NOACCESS);
    if(blocker == NULL)
        return 13;
    status = load_event_module(&second);
    if(status != 0)
        return status;
    if(second == (HMODULE)blocker)
        return 14;

    Sleep(3000);
    status = invoke_event_export(
        second, "event_fixture_one_shot_value", 0x48524531UL);
    if(status == 0)
        status = invoke_event_export(
            second, "event_fixture_persistent_value", 0x48524532UL);
    if(!FreeLibrary(second) && status == 0)
        status = 7;
    if(!VirtualFree(blocker, 0, MEM_RELEASE) && status == 0)
        status = 15;
    return status;
}

static int cycle_event_module(void)
{
    HMODULE module = NULL;
    int status = load_event_module(&module);
    if(status != 0)
        return status;
    if(!FreeLibrary(module))
        return 7;
    return 0;
}

static int stress_event_module(unsigned count)
{
    unsigned index;
    for(index = 0; index < count; ++index)
    {
        int status = cycle_event_module();
        if(status != 0)
            return status;
    }
    return 0;
}

static int expose_event_module_lifecycle(void)
{
    HMODULE module = NULL;
    int status = load_event_module(&module);
    if(status != 0)
        return status;
    Sleep(3000);
    if(!FreeLibrary(module))
        return 7;
    Sleep(3000);
    return 0;
}

static int load_named_module(const wchar_t* dll_name, HMODULE* loaded)
{
    wchar_t path[MAX_PATH];
    wchar_t* separator;
    DWORD length = GetModuleFileNameW(NULL, path, MAX_PATH);
    if(length == 0 || length >= MAX_PATH)
        return 4;
    separator = wcsrchr(path, L'\\');
    if(separator == NULL)
        return 4;
    separator[1] = L'\0';
    if(wcslen(path) + wcslen(dll_name) >= MAX_PATH)
        return 4;
    wcscat(path, dll_name);
    *loaded = LoadLibraryW(path);
    return *loaded == NULL ? 5 : 0;
}

static int run_runtime_decrypt(void)
{
    HMODULE module = NULL;
    int status = load_named_module(L"runtime_decrypt_fixture.dll", &module);
    typedef DWORD(WINAPI* decrypt_fn)(void);
    FARPROC trigger;
    FARPROC flag;
    if(status != 0)
        return status;
    Sleep(1500);
    trigger = GetProcAddress(module, "runtime_decrypt_trigger");
    flag = GetProcAddress(module, "runtime_decrypt_flag");
    if(trigger == NULL || flag == NULL)
        return 10;
    if(((decrypt_fn)trigger)() != 0x48445246UL)
        return 11;
    if(((decrypt_fn)flag)() != 0x48445246UL)
        return 11;
    Sleep(1500);
    if(!FreeLibrary(module))
        return 7;
    return 0;
}

static int fixture_main(int argc, char** argv)
{
    unsigned thread_count = 1;
    unsigned module_stress_count = 0;
    int cycle_module = 0;
    int expose_module_lifecycle = 0;
    int workflow_module_reload = 0;
    int runtime_decrypt = 0;
    int index;
    volatile LONG counter = 0;
    int status;

    for(index = 1; index < argc; ++index)
    {
        if(strcmp(argv[index], "--debug-wait") == 0)
        {
            Sleep(5000);
        }
        else if(strcmp(argv[index], "--event-stress") == 0)
        {
            char* end = NULL;
            unsigned long parsed;
            if(index + 1 >= argc)
                return 8;
            parsed = strtoul(argv[++index], &end, 10);
            if(end == argv[index] || *end != '\0' || parsed == 0 || parsed > 2048)
                return 8;
            thread_count = (unsigned)parsed;
        }
        else if(strcmp(argv[index], "--module-cycle") == 0)
        {
            cycle_module = 1;
        }
        else if(strcmp(argv[index], "--module-stress") == 0)
        {
            char* end = NULL;
            unsigned long parsed;
            if(index + 1 >= argc)
                return 8;
            parsed = strtoul(argv[++index], &end, 10);
            if(end == argv[index] || *end != '\0' || parsed == 0 || parsed > 2048)
                return 8;
            module_stress_count = (unsigned)parsed;
        }
        else if(strcmp(argv[index], "--module-lifecycle-windows") == 0)
        {
            expose_module_lifecycle = 1;
        }
        else if(strcmp(argv[index], "--workflow-module-reload") == 0)
        {
            workflow_module_reload = 1;
        }
        else if(strcmp(argv[index], "--runtime-decrypt") == 0)
        {
            runtime_decrypt = 1;
        }
        else
        {
            return 9;
        }
    }

    if((cycle_module != 0) + (module_stress_count != 0)
           + (expose_module_lifecycle != 0) + (workflow_module_reload != 0)
           + (runtime_decrypt != 0)
       > 1)
        return 9;
    if(cycle_module)
    {
        status = cycle_event_module();
        if(status != 0)
            return status;
    }
    if(module_stress_count != 0)
    {
        status = stress_event_module(module_stress_count);
        if(status != 0)
            return status;
    }
    if(expose_module_lifecycle)
    {
        status = expose_event_module_lifecycle();
        if(status != 0)
            return status;
    }
    if(workflow_module_reload)
    {
        status = run_workflow_module_reload();
        if(status != 0)
            return status;
    }
    if(runtime_decrypt)
    {
        status = run_runtime_decrypt();
        if(status != 0)
            return status;
    }
    status = run_threads(thread_count, &counter);
    if(status != 0)
        return status;

    {
        uint64_t result = fixture_marker(0x1234, (uint64_t)counter);
        printf("HEADLESS_RE_FIXTURE result=%llu counter=%ld\n",
               (unsigned long long)result, (long)counter);
    }
    return counter == (LONG)thread_count ? 0 : 3;
}

#ifdef HEADLESS_RE_FIXTURE_WINDOWS_SUBSYSTEM
int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR command_line, int show_command)
{
    (void)instance;
    (void)previous;
    (void)command_line;
    (void)show_command;
    return fixture_main(__argc, __argv);
}
#else
int main(int argc, char** argv)
{
    return fixture_main(argc, argv);
}
#endif
