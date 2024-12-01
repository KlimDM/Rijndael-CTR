package org.digitalleague.cipher;

public interface Cipher {
    byte[] encrypt(byte[] plainText);

    byte[] decrypt(byte[] cipherText);
}
