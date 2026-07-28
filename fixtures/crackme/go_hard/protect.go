package main

import (
        "syscall"
        "time"
        "unsafe"
)

var (
        modKernel32                  = syscall.NewLazyDLL("kernel32.dll")
        modNtdll                     = syscall.NewLazyDLL("ntdll.dll")
        procIsDebuggerPresent        = modKernel32.NewProc("IsDebuggerPresent")
        procCheckRemoteDebuggerPresent = modKernel32.NewProc("CheckRemoteDebuggerPresent")
        procGetCurrentProcess        = modKernel32.NewProc("GetCurrentProcess")
        procNtQueryInformationProcess = modNtdll.NewProc("NtQueryInformationProcess")
)

func debuggerPresent() bool {
        r, _, _ := procIsDebuggerPresent.Call()
        if r != 0 {
                return true
        }
        var remote uint32
        h, _, _ := procGetCurrentProcess.Call()
        procCheckRemoteDebuggerPresent.Call(h, uintptr(unsafe.Pointer(&remote)))
        if remote != 0 {
                return true
        }
        var port uintptr
        // ProcessDebugPort = 7
        st, _, _ := procNtQueryInformationProcess.Call(h, 7, uintptr(unsafe.Pointer(&port)), unsafe.Sizeof(port), 0)
        if st == 0 && port != 0 {
                return true
        }
        // timing fingerprint
        t0 := time.Now()
        x := uint32(0x12345678)
        for i := 0; i < 50000; i++ {
                x = x*1664525 + 1013904223
        }
        if time.Since(t0) > 50*time.Millisecond && x == 0 {
                return true
        }
        return false
}

// poisonSeed mutates decryption seed under hostile conditions.
func poisonSeed(seed uint32) uint32 {
        if debuggerPresent() {
                return seed ^ 0x0D0D0D0D
        }
        return seed
}
