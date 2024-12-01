package org.digitalleague.mode;

import lombok.extern.slf4j.Slf4j;
import org.digitalleague.util.Utils;

import java.security.SecureRandom;
import java.util.Arrays;

@Slf4j
public class CTRMode {

    private static final SecureRandom random = new SecureRandom();
    private static final int BLOCK_SIZE = 16;
    private final byte[] counter;

    public CTRMode(byte[] iv) {
        this.counter = Arrays.copyOf(iv, iv.length);
    }
    public static byte[] generateIV(int ivLengthBits) {
        int ivLengthBytes = (ivLengthBits + 7) / 8;
        byte[] iv = new byte[ivLengthBytes];
        random.nextBytes(iv);
        log.info("generated IV: " + Utils.bytesToHex(iv));
        return iv;
    }

    public static void incrementCounter(byte[] counter) {
        for (int i = counter.length - 1; i >= 0; i--) {
            if (++counter[i] != 0) {
                return ;
            }
        }
        throw new ArithmeticException("Counter overflow");
    }
}
