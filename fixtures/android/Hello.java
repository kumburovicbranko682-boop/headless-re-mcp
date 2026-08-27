// Source of truth for fixtures/android/classes.dex, used by the Android RE gate
// to exercise androguard's DEX analysis (classes, methods, strings, xrefs) with
// a real compiled DEX rather than a placeholder. Compiling a DEX needs the
// Android build tools, which the test environment does not have, so the built
// classes.dex is committed alongside this source and this file records how it
// was produced so it can be regenerated deterministically:
//
//   javac --release 8 -d classes fixtures/android/Hello.java
//   java -cp r8.jar com.android.tools.r8.D8 --release --min-api 21 \
//       --output fixtures/android classes/com/example/hello/Hello.class
//
// (r8.jar is Google's D8/R8 from maven.google.com; any recent version works.)
// The gate asserts the class name, the method names, SECRET, and that run()
// calls greet() (an intra-DEX xref), so keep those in sync with
// tests/integration/_apk_fixture.py EXPECTED if this changes.
package com.example.hello;

public class Hello {
    public static final String SECRET = "androguard-gate-STRINGMARKER";

    public String greet(String name) {
        return "hello " + name + SECRET;
    }

    public int add(int a, int b) {
        return a + b;
    }

    // Calls greet() and add() so androguard sees an intra-DEX xref into them,
    // which is what the apk.xrefs gate asserts.
    public String run(String name) {
        return greet(name) + add(1, 2);
    }
}
