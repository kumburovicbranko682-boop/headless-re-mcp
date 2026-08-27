package com.headlessre.sample;

/** A second class so the DEX has more than one type and a static call target. */
public class Crypto {
    public static String transform(String input) {
        return "HEADLESS_RE_TRANSFORMED:" + input;
    }
}
