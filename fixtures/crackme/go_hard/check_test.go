package main

import "testing"

func TestCheckLicense(t *testing.T) {
        if !checkLicense("X9m#Kp2$Lv7@Qn4!") {
                t.Fatal("real key rejected")
        }
        for _, bad := range []string{"fork", "admin", "X9m#Kp2$Lv7@Qn4?", "N1ghtF0x_MCP!", ""} {
                if checkLicense(bad) {
                        t.Fatalf("false positive: %q", bad)
                }
        }
}
