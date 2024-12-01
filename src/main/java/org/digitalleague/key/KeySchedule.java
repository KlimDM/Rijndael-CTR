package org.digitalleague.key;

import org.digitalleague.cipher.util.SBox;

public class KeySchedule {

    private final static byte[][] Rcon = new byte[][] {
            new byte[] {0x01, 0x00, 0x00, 0x00},
            new byte[] {0x02, 0x00, 0x00, 0x00},
            new byte[] {0x04, 0x00, 0x00, 0x00},
            new byte[] {0x08, 0x00, 0x00, 0x00},
            new byte[] {0x10, 0x00, 0x00, 0x00},
            new byte[] {0x20, 0x00, 0x00, 0x00},
            new byte[] {0x40, 0x00, 0x00, 0x00},
            new byte[] {(byte)0x80, 0x00, 0x00, 0x00},
            new byte[] {0x1B, 0x00, 0x00, 0x00},
            new byte[] {0x36, 0x00, 0x00, 0x00},
            new byte[] {0x6c, 0x00, 0x00, 0x00},
            new byte[] {(byte)0xd8, 0x00, 0x00, 0x00},
            new byte[] {(byte)0xab, 0x00, 0x00, 0x00},
            new byte[] {0x4d, 0x00, 0x00, 0x00},
    };
    public byte[][] keyExpansion(byte[] key) {
        int Nk = key.length / 4; // Количество слов в ключе
        int Nr = Nk + 6; // Число раундов шифрования
        int Nb = 4;
        byte[][] roundKeys = new byte[Nb * (Nr + 1)][4]; // Размер массива, который будет содержать все раундовые ключи

        for (int i = 0; i < Nk; i++) {
            roundKeys[i] = new byte[] {key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]};
        }

        // Генерация оставшихся слов
        for (int i = Nk; i < Nb * (Nr + 1); i++) {
            byte[] tempWord = roundKeys[i - 1];
            if (i % Nk == 0) {
                tempWord = arrayXor(subWord(rotWord(tempWord)), Rcon[i / Nk - 1]);
            } else if (Nk > 6 && i % Nk == 4) {
                tempWord = subWord(tempWord);
            }
            roundKeys[i] = arrayXor(roundKeys[i - Nk], tempWord);
        }

        return roundKeys;
    }

    private byte[] subWord(byte[] word) {
        byte[] result = new byte[word.length];
        for (int i = 0; i < word.length; i++) {
            result[i] = SBox.getValue(word[i]);
        }
        return result;
    }

    private byte[] rotWord(byte[] word) {
        byte[] result = new byte[word.length];
        result[0] = word[1];
        result[1] = word[2];
        result[2] = word[3];
        result[3] = word[0];
        return result;
    }

    private byte[] arrayXor(byte[] arr1, byte[] arr2) {
        byte[] result = new byte[arr1.length];
        for (int i = 0; i < arr1.length; i++) {
            result[i] = (byte) (arr1[i] ^ arr2[i]);
        }
        return result;
    }
}
