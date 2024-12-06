package org.digitalleague.cipher.impl;

import org.digitalleague.cipher.BaseCipher;
import org.digitalleague.cipher.Cipher;
import org.digitalleague.key.KeySchedule;

import java.util.Arrays;

/**
 * Класс для непосредственного шифрования произвольного массива байтов.
 */
public class CipherImpl implements Cipher {
    private static final int DEFAULT_BLOCK_SIZE = 16;
    private static final KeySchedule keySchedule = new KeySchedule();
    private final byte[][] roundKeys;
    private final BaseCipher cipher;

    private CipherImpl(byte[] key) {
        cipher = switch (key.length) {
            case 16 -> new RijndaelBaseImpl(RijndaelBaseImpl.KEY_LENGTH.KEY_128);
            case 24 -> new RijndaelBaseImpl(RijndaelBaseImpl.KEY_LENGTH.KEY_192);
            case 32 -> new RijndaelBaseImpl(RijndaelBaseImpl.KEY_LENGTH.KEY_256);
            default -> throw new IllegalArgumentException("Invalid key length: must be 128, 192 or 256 bits");
        };
        this.roundKeys = keySchedule.keyExpansion(key);
    }

    public static CipherImpl createInstance(byte[] key) {
        return new CipherImpl(key);
    }

    /**
     * Основной метод библиотеки. Разделяет полученные байты по блокам и выполняет шифрование,
     * дополняя последний блок при необходимости.
     * @param plainText - массив байтов любого размера (пустой список не шифруется, этот случай должен
     *                    обрабатываться в вызывающей программе в зависимости от требований)
     * @return cipherText - открытый текст (список зашифрованных байтов), который можно передавать раздельно от ключа
     */
    public byte[] encrypt(byte[] plainText) {
        byte[] paddedPlainText = this.addPadding(plainText);
        byte[] result = new byte[paddedPlainText.length];

        for (int i = 0; i < paddedPlainText.length; i += DEFAULT_BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(paddedPlainText, i, i + DEFAULT_BLOCK_SIZE);
            byte[] cipherBlock = this.cipher.encryptBlock(block, roundKeys);
            System.arraycopy(cipherBlock, 0, result, i, DEFAULT_BLOCK_SIZE);
        }
        return result;
    }


    /**
     * Основной метод библиотеки. Разделяет полученные байты по блокам и выполняет шифрование,
     * дополняя последний блок при необходимости.
     * @param cipherText - массив байтов размера, кратного размеру блока
     * @return plainText - дешифрованное сообщение (в формате массива байтов, кодировка должна обрабатываться в вызывабщей программе
     */
    public byte[] decrypt(byte[] cipherText) {
        byte[] result = new byte[cipherText.length];

        if (cipherText.length % 16 != 0) {
            throw new IllegalArgumentException("expected cipherText length as multiplication of 16, but got " + cipherText.length);
        }

        for (int i = 0; i < cipherText.length; i += DEFAULT_BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(cipherText, i, i + DEFAULT_BLOCK_SIZE);
            byte[] cipherBlock = this.cipher.decryptBlock(block, roundKeys);
            System.arraycopy(cipherBlock, 0, result, i, DEFAULT_BLOCK_SIZE);
        }

        return removePadding(result);
    }

    /**
     * Padding (дополнение) блоков исходного текста. Выполняется в соответствии с PKCS#7-алгоритмом
     * @param plainText
     * @return
     */
    private byte[] addPadding(byte[] plainText) {
        if (plainText.length % DEFAULT_BLOCK_SIZE == 0) {
            return plainText;
        }
        int paddingSize = DEFAULT_BLOCK_SIZE - (plainText.length % DEFAULT_BLOCK_SIZE);
        byte[] paddedPlainText = new byte[plainText.length + paddingSize];
        System.arraycopy(plainText, 0, paddedPlainText, 0, plainText.length);
        Arrays.fill(paddedPlainText, plainText.length, plainText.length + paddingSize, (byte) paddingSize);
        return paddedPlainText;
    }

    /**
     * Удаление возможного Padding (Дополнения) после дешифровки декста
     * @param cipherText
     * @return
     */
    private byte[] removePadding(byte[] cipherText) {
        if (cipherText.length == 0) {
            return cipherText;
        }
        int paddingSize = cipherText[cipherText.length - 1];
        if (paddingSize < 1 || paddingSize > DEFAULT_BLOCK_SIZE || paddingSize > cipherText.length) {
            return cipherText;
        }
        for (int i = cipherText.length - paddingSize; i < cipherText.length; i++) {
            if (cipherText[i] != paddingSize) {
                return cipherText;
            }
        }
        byte[] unpaddedText = new byte[cipherText.length - paddingSize];
        System.arraycopy(cipherText, 0, unpaddedText, 0, cipherText.length - paddingSize);
        return unpaddedText;
    }
}
