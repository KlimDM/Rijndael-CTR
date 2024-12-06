package org.digitalleague.cipher.impl;

import org.digitalleague.function.PolynomialGF256;
import org.digitalleague.cipher.util.SBox;
import org.digitalleague.cipher.BaseCipher;

import java.util.Arrays;

import static org.digitalleague.function.PolynomialGF256.multiply;

/**
 * Основная логика шифрования алгоритмом Rijndael (AES).
 * Спецификация AES определяет длину блока (128 бит), допустимые длины ключей (128, 192, 256 бит)
 * и соответственно число раундов шифрования (10, 12, 14 раундов).
 * Спецификация алгоритма оперирует "словами" (word) - массивами из 4 байтов. Все неключевые операции выполняются над
 * матрицей состояний (state - матрица из 4 слов, т.е. размером 4х4 байта).
 * Все алгебрические операции над байтами производятся как для полиномов Pn(7) над полем GF(2**8). Реализация этих операция
 * выполнена в отдельном классе
 */
public class RijndaelBaseImpl implements BaseCipher {
    private static final int Nb = 4; //  Длина шифруемого блока в словах (4-байтовых массивах)
    private final int Nk; //  Длина ключа в словах
    private final int Nr; //  Число раундов шифрования (зависит только от размеров ключа)

    public RijndaelBaseImpl(KEY_LENGTH keyLength) {
        this.Nk = keyLength.value / 32;
        this.Nr = this.Nk + 6;
    }

    /**
     * Добавление соответствующего слова раундового ключа к соответствующему слову состояния
     * @param state - матрица состояний
     * @param roundKey - подмножество множества сгенерированных раундовых ключей.
     */
    private void addRoundKey(byte[][] state, byte[][] roundKey) {
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < Nb; i++) {
                state[j][i] = PolynomialGF256.add(state[j][i], roundKey[i][j]);
            }
        }
    }

    /**
     * Шифрование 128-битного блока данных. Начинается с добавления начального ключа. После этого n-1 раундов шифрования
     * с выполнением методов в строгом порядке. Во время финального раунда шифрования не выполняется метод mixColumns.
     * @param plainBlock - блок из открытого текста
     * @param roundKeys - матрица расписания ключей
     * @return plainBlock - массив зашифрованных байтов
     */
    public byte[] encryptBlock(byte[] plainBlock, byte[][] roundKeys) {

        byte[][] state = createState(plainBlock); //  Создаем матрицу состояний и заполняем данными

        addRoundKey(state, Arrays.copyOfRange(roundKeys, 0, Nb)); // Начальный раунд

        for (int round = 1; round < Nr; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, Arrays.copyOfRange(roundKeys, round * Nb, (round + 1) * Nb));
        }

        subBytes(state);
        shiftRows(state);
        addRoundKey(state, Arrays.copyOfRange(roundKeys, Nr * Nb, (Nr + 1) * Nb)); // Финальный раунд шифрования

        return stateToBytes(state);
    }

    /**
     * Шифрование 128-битного блока данных. Начинается с добавления начального ключа. После этого n-1 раундов шифрования
     * с выполнением обратных (inv...) методов. Во время финального раунда шифрования не выполняется метод invMixColumns.
     * @param cipherBlock - зашифрованный блок
     * @param roundKeys - матрица расписания ключей
     * @return plainBlock - массив расшифрованных байтов
     */
    public byte[] decryptBlock(byte[] cipherBlock, byte[][] roundKeys) {

        byte[][] state = createState(cipherBlock);

        addRoundKey(state, Arrays.copyOfRange(roundKeys, Nr * Nb, Nb * (Nr + 1)));

        for (int round = Nr - 1; round > 0; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, Arrays.copyOfRange(roundKeys, round * Nb, (round + 1) * Nb));
            invMixColumns(state);
        }

        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, Arrays.copyOfRange(roundKeys, 0, Nb)); // Финальный раунд шифрования

        return stateToBytes(state);
    }

    /**
     * Генерация матрица состояния (соответствует спецификации, т.е. column-major indexing).
     * Каждое слово представляец собой вектор-столбец.
     * @param block - исходный массив байтов (обязательно 16-байтовый)
     * @return state - матрица состояния
     */
    private byte[][] createState(byte[] block) {
        byte[][] state = new byte[4][Nb];
        int k = 0;

        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < Nb; j++) {
                state[j][i] = block[k++];
            }
        }
        return state;
    }

    /**
     * Генерация массива байтов из матрицы состояния
     * @param state - матрица состояния
     */
    private byte[] stateToBytes(byte[][] state) {
        byte[] block = new byte[Nb * Nb];
        int k = 0;

        for (int i = 0; i < Nb; i++) {
            for (int j = 0; j < Nb; j++) {
                block[k++] = state[j][i];
            }
        }
        return block;
    }

    /**
     * Замена каждого байта в матрице состояния на соответствующий байт из таблицы s-box.
     * Таблица находится в классе S-Box (присутвствует в спецификации алгоритма, как результат выполнения уравнения для
     * каждого из 255 байтов).
     * @param state - матрица состояния
     */
    public void subBytes(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = SBox.getValue(state[i][j]);
            }
        }
    }

    /**
     * Обратная замена байтов состояния (т.е. если subBytes(x) = y, то invSubBytes(y) = x).
     * @param state - матрица состояния
     */
    public void invSubBytes(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = SBox.getInverseValue(state[i][j]);
            }
        }
    }

    /**
     * Сдвиги для каждой строки состояния определены в спецификации (1 строка состояния не изменяется)
     * @param state - матрица состояния
     */
    public void shiftRows(byte[][] state) {
        byte[] shifts = new byte[] {1, 2, 3};

        for (int i = 1; i < state.length; i++) {
            byte[] shiftedArray = new byte[Nb];

            System.arraycopy(state[i], shifts[i-1], shiftedArray, 0, Nb - shifts[i-1]);
            System.arraycopy(state[i], 0, shiftedArray, Nb - shifts[i-1], shifts[i-1]);
            state[i] = shiftedArray;
        }
    }

    /**
     * Обратное преобразование строк состояния (выполняется как сдвиг массива вправо, а не влево как у shiftRows)
     * @param state - матрица состояния
     */
    public void invShiftRows(byte[][] state) {
        byte[] shifts = new byte[] {1, 2, 3};

        for (int i = 1; i < state.length; i++) {
            byte[] shiftedArray = new byte[Nb];

            System.arraycopy(state[i], Nb - shifts[i-1], shiftedArray, 0, shifts[i-1]);
            System.arraycopy(state[i], 0, shiftedArray, shifts[i-1], Nb - shifts[i-1]);
            state[i] = shiftedArray;
        }
    }

    /**
     * Преобразование столбцов - каждый столбец состояния преобразовывается в соответствии с матричным уравнением (Y = AX + B), описанным в спецификации
     * Здесь multiply(x, y) - умножение двух полиномов над полиномов, представленных как байты x, y, в соответствии с
     * алгеброй конечных полей. ^ - побитовое или - сложение двух полиномов над конечным полем
     * @param state - матрица состояния
     */
    public void mixColumns(byte[][] state) {
        byte[][] stateCopy = Arrays.stream(state).map(byte[]::clone).toArray(byte[][]::new);

        for (int c = 0; c < 4; c++) {
            state[0][c] = (byte)((multiply((byte)0x02, stateCopy[0][c])) ^ multiply((byte)0x03, stateCopy[1][c]) ^ stateCopy[2][c] ^ stateCopy[3][c]);
            state[1][c] = (byte)(stateCopy[0][c] ^ multiply((byte)0x02, stateCopy[1][c]) ^ multiply((byte)0x03, stateCopy[2][c]) ^ stateCopy[3][c]);
            state[2][c] = (byte)(stateCopy[0][c] ^ stateCopy[1][c] ^ multiply((byte)0x02, stateCopy[2][c]) ^ multiply((byte)0x03, stateCopy[3][c]));
            state[3][c] = (byte)((multiply((byte)0x03, stateCopy[0][c])) ^ stateCopy[1][c] ^ stateCopy[2][c] ^ multiply((byte)0x02, stateCopy[3][c]));
        }
    }

    /**
     * Преобразование столбцов - каждый столбец состояния преобразовывается в соответствии с матричным уравнением (X = A'Y - B).
     * где A' - матрица, обратная к A
     * @param state - матрица состояния
     */
    public void invMixColumns(byte[][] state) {
        byte[][] stateCopy = Arrays.stream(state).map(byte[]::clone).toArray(byte[][]::new);

        for (int c = 0; c < 4; c++) {
            state[0][c] = (byte)((multiply((byte)0x0e, stateCopy[0][c])) ^ multiply((byte)0x0b, stateCopy[1][c]) ^ multiply((byte)0x0d, stateCopy[2][c]) ^ multiply((byte)0x09, stateCopy[3][c]));
            state[1][c] = (byte)(multiply((byte)0x09, stateCopy[0][c]) ^ multiply((byte)0x0e, stateCopy[1][c]) ^ multiply((byte)0x0b, stateCopy[2][c]) ^ multiply((byte)0x0d, stateCopy[3][c]));
            state[2][c] = (byte)(multiply((byte)0x0d, stateCopy[0][c]) ^ multiply((byte)0x09, stateCopy[1][c]) ^ multiply((byte)0x0e, stateCopy[2][c]) ^ multiply((byte)0x0b, stateCopy[3][c]));
            state[3][c] = (byte)((multiply((byte)0x0b, stateCopy[0][c])) ^ multiply((byte)0x0d, stateCopy[1][c]) ^ multiply((byte)0x09, stateCopy[2][c]) ^ multiply((byte)0x0e, stateCopy[3][c]));
        }
    }


    public enum KEY_LENGTH {
        KEY_128(128),
        KEY_192(192),
        KEY_256(256);

        private final int value;

        KEY_LENGTH(int value) {
            this.value = value;
        }

        public int getKeyLength() {
            return value;
        }
    }
}
