#include <windows.h>

#define IDC_VALUE 1001
#define IDC_APPLY 1002
#define WM_FIXTURE_TRANSFORM (WM_APP + 1)

__declspec(dllexport) __declspec(noinline) unsigned WINAPI gui_fixture_transform(
    unsigned value)
{
    return (value ^ 0x5245U) + 7U;
}

static LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    (void)lparam;
    switch(message)
    {
    case WM_CREATE:
        CreateWindowW(L"STATIC", L"Fixture value:", WS_CHILD | WS_VISIBLE,
                      16, 18, 100, 20, hwnd, NULL, NULL, NULL);
        CreateWindowW(L"EDIT", L"42", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER,
                      120, 16, 120, 24, hwnd, (HMENU)IDC_VALUE, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Transform", WS_CHILD | WS_VISIBLE,
                      16, 54, 100, 28, hwnd, (HMENU)IDC_APPLY, NULL, NULL);
        return 0;
    case WM_COMMAND:
        if(LOWORD(wparam) == IDC_APPLY)
        {
            BOOL valid = FALSE;
            unsigned value = GetDlgItemInt(hwnd, IDC_VALUE, &valid, FALSE);
            if(valid)
                PostMessageW(hwnd, WM_FIXTURE_TRANSFORM, (WPARAM)value, 0);
            else
                SetWindowTextW(hwnd, L"Headless RE Fixture - invalid value");
        }
        return 0;
    case WM_FIXTURE_TRANSFORM:
    {
        wchar_t title[96] = {0};
        unsigned value = gui_fixture_transform((unsigned)wparam);
        wsprintfW(title, L"Headless RE Fixture - result %u", value);
        SetWindowTextW(hwnd, title);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(hwnd, message, wparam, lparam);
    }
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR command, int show)
{
    (void)previous;
    (void)command;
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = instance;
    wc.lpszClassName = L"HeadlessReFixtureWindow";
    if(!RegisterClassW(&wc))
        return 2;
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"Headless RE Fixture",
                                WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                                300, 140, NULL, NULL, instance, NULL);
    if(hwnd == NULL)
        return 3;
    /* Debuggers often pass SW_HIDE as nCmdShow; force a real top-level window. */
    (void)show;
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    MSG msg;
    while(GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
