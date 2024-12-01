import org.digitalleague.key.KeySchedule;
import org.digitalleague.cipher.impl.RijndaelBaseImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class RoundTest {
    private final RijndaelBaseImpl cipher = new RijndaelBaseImpl(RijndaelBaseImpl.KEY_LENGTH.KEY_128);
    private final KeySchedule keySchedule = new KeySchedule();

    @Test
    public void test128key() {

        byte[] plainText = new byte[] {
                0x32, (byte)0x43, (byte)0xf6, (byte)0xa8,
                (byte)0x88, 0x5a, 0x30, (byte)0x8d,
                (byte)0x31, (byte)0x31, (byte)0x98, (byte)0xa2,
                (byte)0xe0, (byte)0x37, (byte)0x07, (byte)0x34
        }; // 16-байтовый текст для шифрования

        byte[] key = new byte[] {
                0x2b, 0x7e, 0x15, 0x16, // w1
                0x28, (byte)0xae, (byte)0xd2, (byte)0xa6, // w2
                (byte)0xab, (byte)0xf7, 0x15, (byte)0x88, // w3
                0x09, (byte)0xcf, 0x4f, 0x3c // w4
        };

        byte[][] roundKeys = keySchedule.keyExpansion(key);
        byte[] result = cipher.encryptBlock(plainText, roundKeys);

        byte[] expected = new byte[] {
                0x39, 0x25, (byte)0x84, 0x1d,
                0x02, (byte)0xdc, 0x09, (byte)0xfb,
                (byte)0xdc, 0x11, (byte)0x85, (byte)0x97,
                0x19, 0x6a, 0x0b, 0x32
        };

        Assertions.assertArrayEquals(expected, result);
    }

    @Test
    public void test128keyInv() {

        byte[] ciphertext = new byte[] {
                0x39, 0x25, (byte)0x84, 0x1d,
                0x02, (byte)0xdc, 0x09, (byte)0xfb,
                (byte)0xdc, 0x11, (byte)0x85, (byte)0x97,
                0x19, 0x6a, 0x0b, 0x32
        };

        byte[] key = new byte[] {
                0x2b, 0x7e, 0x15, 0x16, // w1
                0x28, (byte)0xae, (byte)0xd2, (byte)0xa6, // w2
                (byte)0xab, (byte)0xf7, 0x15, (byte)0x88, // w3
                0x09, (byte)0xcf, 0x4f, 0x3c // w4
        };

        byte[][] roundKeys = keySchedule.keyExpansion(key);
        byte[] result = cipher.decryptBlock(ciphertext, roundKeys);

        byte[] expected = new byte[] {
            0x32, 0x43, (byte)0xf6, (byte)0xa8,
            (byte)0x88, 0x5a, 0x30, (byte)0x8d,
            0x31, 0x31, (byte)0x98, (byte)0xa2,
            (byte)0xe0, 0x37, 0x07, 0x34
        };

        Assertions.assertArrayEquals(expected, result);
    }

    @Test
    public void test128key2() {

        byte[] plainText = new byte[] {
                      0x00, (byte)0x11, (byte)0x22, (byte)0x33,
                (byte)0x44,       0x55, (byte)0x66, (byte)0x77,
                (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb,
                (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff
        };

        byte[] key = new byte[] {
                      0x00,       0x01,       0x02,       0x03, // w1
                      0x04, (byte)0x05, (byte)0x06, (byte)0x07, // w2
                (byte)0x08, (byte)0x09,       0x0a, (byte)0x0b, // w3
                      0x0c, (byte)0x0d,       0x0e,       0x0f // w4
        };

        byte[][] roundKeys = keySchedule.keyExpansion(key);
        byte[] result = cipher.encryptBlock(plainText, roundKeys);


        byte[] expected = new byte[] {
            0x69, (byte)0xc4, (byte)0xe0, (byte)0xd8,
            0x6a, 0x7b, 0x04, 0x30,
            (byte)0xd8, (byte)0xcd, (byte)0xb7, (byte)0x80,
            0x70, (byte)0xb4, (byte)0xc5, 0x5a
        };

        Assertions.assertArrayEquals(expected, result);
    }

    @Test
    public void testInv128key2Inv() {

        byte[] ciphertext = new byte[] {
                0x69, (byte)0xc4, (byte)0xe0, (byte)0xd8,
                0x6a, 0x7b, 0x04, 0x30,
                (byte)0xd8, (byte)0xcd, (byte)0xb7, (byte)0x80,
                0x70, (byte)0xb4, (byte)0xc5, 0x5a
        };

        byte[] expected = new byte[] {
            0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
            (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb,
            (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff
        };

        byte[] key = new byte[] {
                0x00, 0x01, 0x02, 0x03, // w1
                0x04, (byte)0x05, (byte)0x06, (byte)0x07, // w2
                (byte)0x08, (byte)0x09, 0x0a, (byte)0x0b, // w3
                0x0c, (byte)0x0d, 0x0e, 0x0f // w4
        };

        byte[][] roundKeys = keySchedule.keyExpansion(key);
        byte[] result = cipher.decryptBlock(ciphertext, roundKeys);

        Assertions.assertArrayEquals(expected, result);
    }

}
