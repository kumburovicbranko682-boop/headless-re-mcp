package com.example.gate;

public class Helper {
    public static long fib(int n) {
        long a = 0;
        long b = 1;
        for (int i = 0; i < n; i++) {
            long t = a + b;
            a = b;
            b = t;
        }
        return a;
    }
}
