package com.github.martoreto.aauto.vex.vag;

import java.util.Random;

public final class ExlapUtils {
    public static String generateSessionId() {
        final String alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            sb.append(alphabet.charAt(new Random().nextInt(alphabet.length())));
        }
        return sb.toString();
    }
}
