package org.digitalleague.cipher;

public interface BaseCipher {
    byte[] encryptBlock(byte[] plainText, byte[][] roundKeys);
    byte[] decryptBlock(byte[] cipherText, byte[][] roundKeys);
}
