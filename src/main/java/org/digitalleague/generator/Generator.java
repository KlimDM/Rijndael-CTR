package org.digitalleague.generator;

import lombok.extern.slf4j.Slf4j;

import java.security.SecureRandom;

@Slf4j
public class Generator {
    SecureRandom random = new SecureRandom();
    public byte[] generateKey(int keyLengthBits) {
        int keyLengthBytes = (keyLengthBits + 7) / 8;
        byte[] key = new byte[keyLengthBytes];
        random.nextBytes(key);
        return key;
    }
}
