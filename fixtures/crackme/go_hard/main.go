package main

import (
        "syscall"
        "unsafe"
)

var (
        user32                       = syscall.NewLazyDLL("user32.dll")
        kernel32                     = syscall.NewLazyDLL("kernel32.dll")
        procRegisterClassExW         = user32.NewProc("RegisterClassExW")
        procCreateWindowExW          = user32.NewProc("CreateWindowExW")
        procShowWindow               = user32.NewProc("ShowWindow")
        procUpdateWindow             = user32.NewProc("UpdateWindow")
        procGetMessageW              = user32.NewProc("GetMessageW")
        procTranslateMessage         = user32.NewProc("TranslateMessage")
        procDispatchMessageW         = user32.NewProc("DispatchMessageW")
        procPostQuitMessage          = user32.NewProc("PostQuitMessage")
        procDefWindowProcW           = user32.NewProc("DefWindowProcW")
        procGetWindowTextW           = user32.NewProc("GetWindowTextW")
        procMessageBoxW              = user32.NewProc("MessageBoxW")
        procLoadCursorW              = user32.NewProc("LoadCursorW")
        procGetModuleHandleW         = kernel32.NewProc("GetModuleHandleW")
        procSetWindowTextW           = user32.NewProc("SetWindowTextW")
        procDestroyWindow            = user32.NewProc("DestroyWindow")
)

const (
        WS_OVERLAPPEDWINDOW = 0x00CF0000
        WS_VISIBLE          = 0x10000000
        WS_CHILD            = 0x40000000
        WS_TABSTOP          = 0x00010000
        WS_BORDER           = 0x00800000
        ES_AUTOHSCROLL      = 0x0080
        BS_DEFPUSHBUTTON    = 0x0001
        CW_USEDEFAULT       = 0x80000000
        SW_SHOW             = 5
        WM_DESTROY          = 0x0002
        WM_COMMAND          = 0x0111
        WM_CREATE           = 0x0001
        IDC_ARROW           = 32512
        BN_CLICKED          = 0
        ID_EDIT             = 1001
        ID_BTN              = 1002
        ID_STATUS           = 1003
        MB_OK               = 0
        MB_ICONINFORMATION  = 0x40
        MB_ICONERROR        = 0x10
)

type wndClassEx struct {
        size       uint32
        style      uint32
        wndProc    uintptr
        clsExtra   int32
        wndExtra   int32
        instance   syscall.Handle
        icon       syscall.Handle
        cursor     syscall.Handle
        background syscall.Handle
        menuName   *uint16
        className  *uint16
        iconSm     syscall.Handle
}

type point struct{ x, y int32 }
type msg struct {
        hwnd    syscall.Handle
        message uint32
        wParam  uintptr
        lParam  uintptr
        time    uint32
        pt      point
}

var (
        hEdit   syscall.Handle
        hStatus syscall.Handle
)

func utf16(s string) *uint16 {
        p, _ := syscall.UTF16PtrFromString(s)
        return p
}

func messageBox(title, body string, flags uint32) {
        procMessageBoxW.Call(0, uintptr(unsafe.Pointer(utf16(body))), uintptr(unsafe.Pointer(utf16(title))), uintptr(flags))
}

func getText(hwnd syscall.Handle) string {
        buf := make([]uint16, 256)
        n, _, _ := procGetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
        return syscall.UTF16ToString(buf[:n])
}

func setText(hwnd syscall.Handle, s string) {
        procSetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(utf16(s))))
}

func wndProc(hwnd syscall.Handle, msgID uint32, wParam, lParam uintptr) uintptr {
        switch msgID {
        case WM_CREATE:
                hInst, _, _ := procGetModuleHandleW.Call(0)
                // title label
                procCreateWindowExW.Call(
                        0,
                        uintptr(unsafe.Pointer(utf16("STATIC"))),
                        uintptr(unsafe.Pointer(utf16("KeyForge GO Hard — enter license"))),
                        WS_CHILD|WS_VISIBLE,
                        20, 18, 400, 20,
                        uintptr(hwnd), 0, hInst, 0,
                )
                hEditRaw, _, _ := procCreateWindowExW.Call(
                        0,
                        uintptr(unsafe.Pointer(utf16("EDIT"))),
                        0,
                        WS_CHILD|WS_VISIBLE|WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL,
                        20, 50, 320, 26,
                        uintptr(hwnd), ID_EDIT, hInst, 0,
                )
                hEdit = syscall.Handle(hEditRaw)
                procCreateWindowExW.Call(
                        0,
                        uintptr(unsafe.Pointer(utf16("BUTTON"))),
                        uintptr(unsafe.Pointer(utf16("Unlock"))),
                        WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON,
                        350, 48, 80, 30,
                        uintptr(hwnd), ID_BTN, hInst, 0,
                )
                st, _, _ := procCreateWindowExW.Call(
                        0,
                        uintptr(unsafe.Pointer(utf16("STATIC"))),
                        uintptr(unsafe.Pointer(utf16("status: idle"))),
                        WS_CHILD|WS_VISIBLE,
                        20, 95, 410, 20,
                        uintptr(hwnd), ID_STATUS, hInst, 0,
                )
                hStatus = syscall.Handle(st)
                procCreateWindowExW.Call(
                        0,
                        uintptr(unsafe.Pointer(utf16("STATIC"))),
                        uintptr(unsafe.Pointer(utf16("hint: static strings are not your friend"))),
                        WS_CHILD|WS_VISIBLE,
                        20, 130, 410, 20,
                        uintptr(hwnd), 0, hInst, 0,
                )
                return 0
        case WM_COMMAND:
                id := wParam & 0xffff
                notif := (wParam >> 16) & 0xffff
                if id == ID_BTN && notif == BN_CLICKED {
                        key := getText(hEdit)
                        if key == "" {
                                setText(hStatus, "status: empty")
                                messageBox("KeyForge", "Empty license.", MB_OK|MB_ICONERROR)
                                return 0
                        }
                        if checkLicense(key) {
                                setText(hStatus, "status: UNLOCKED")
                                messageBox("KeyForge", "Access granted.", MB_OK|MB_ICONINFORMATION)
                        } else {
                                setText(hStatus, "status: DENIED")
                                messageBox("KeyForge", "Invalid license.", MB_OK|MB_ICONERROR)
                        }
                        return 0
                }
        case WM_DESTROY:
                procPostQuitMessage.Call(0)
                return 0
        }
        r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msgID), wParam, lParam)
        return r
}

func main() {
        hInst, _, _ := procGetModuleHandleW.Call(0)
        className := utf16("KeyForgeGoHardWnd")
        cursor, _, _ := procLoadCursorW.Call(0, IDC_ARROW)

        wc := wndClassEx{
                size:      uint32(unsafe.Sizeof(wndClassEx{})),
                wndProc:   syscall.NewCallback(wndProc),
                instance:  syscall.Handle(hInst),
                cursor:    syscall.Handle(cursor),
                className: className,
        }
        procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

        hwnd, _, _ := procCreateWindowExW.Call(
                0,
                uintptr(unsafe.Pointer(className)),
                uintptr(unsafe.Pointer(utf16("KeyForge GO Hard v3"))),
                WS_OVERLAPPEDWINDOW|WS_VISIBLE,
                CW_USEDEFAULT, CW_USEDEFAULT, 470, 210,
                0, 0, hInst, 0,
        )
        procShowWindow.Call(hwnd, SW_SHOW)
        procUpdateWindow.Call(hwnd)

        var m msg
        for {
                ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
                if int32(ret) <= 0 {
                        break
                }
                procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
                procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
        }
}
