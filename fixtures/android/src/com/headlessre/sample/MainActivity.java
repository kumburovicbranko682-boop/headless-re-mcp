package com.headlessre.sample;

/**
 * Launcher activity for the fixture. {@link #run()} calls {@link #secret()} and
 * {@link Crypto#transform(String)} so the DEX carries real method cross-refs for
 * the androguard xref gate to find.
 */
public class MainActivity {
    public String secret() {
        return "HEADLESS_RE_SECRET_TOKEN";
    }

    public String run() {
        String value = secret();
        return Crypto.transform(value);
    }
}
