package com.drivetrain.sectest;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Clean baseline crypto helper. Uses SecureRandom and a modern algorithm.
 * Future branches may introduce weak-crypto variants (MD5, DES, ECB,
 * java.util.Random for tokens) to test the scanner.
 */
public final class SafeCrypto {

    private static final SecureRandom RNG = new SecureRandom();

    private SafeCrypto() {}

    public static String newToken(int numBytes) {
        byte[] buf = new byte[numBytes];
        RNG.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
