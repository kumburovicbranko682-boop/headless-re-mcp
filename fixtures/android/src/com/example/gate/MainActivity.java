package com.example.gate;

/**
 * A tiny, deliberately boring activity that gives the androguard static-analysis
 * gate something real to chew on: a recognizable string constant, an integer
 * method, and a String method that (via `+`) calls StringBuilder.append -- an
 * *external* framework method whose in-app callers the xrefs gate then resolves.
 */
public class MainActivity {
    public String secret() {
        return "H3adl3ss_marker";
    }

    public int add(int a, int b) {
        return a + b;
    }

    public String greet(String who) {
        return "hello " + who;
    }
}
