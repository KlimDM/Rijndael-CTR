import lombok.SneakyThrows;
import org.digitalleague.cipher.impl.CipherImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class CipherImplTest {
    static String STRING_PLAINTEXT = "Test plaintext to cipher with Rijndael";
    static String STRING_KEY = "TestKeyToCheckCipherOnDifferentKeySizes";
    private CipherImpl cipher = CipherImpl.createInstance(key128);
    public static byte[] key128 = new byte[] {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
        (byte)0xab, (byte)0xf7, 0x15, (byte)0x88,
        0x09, (byte)0xcf, 0x4f, 0x3c
    };

    public static byte[] key192 = new byte[] {
            0x2b, 0x7e, 0x15, 0x16,
            0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, 0x15, (byte)0x88,
            0x09, (byte)0xcf, 0x4f, 0x3c,
            0x12, (byte)0xda, 0x05, (byte)0xfe,
            0x54, (byte)0xbc, 0x11, (byte)0xae
    };

    public static byte[] key256 = new byte[] {
            0x2b, 0x7e, 0x15, 0x16,
            0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, 0x15, (byte)0x88,
            0x09, (byte)0xcf, 0x4f, 0x3c,
            0x12, (byte)0xda, 0x05, (byte)0xfe,
            0x54, (byte)0xbc, 0x11, (byte)0xae,
            0x42, (byte)0xab, (byte)0xcb, (byte)0xff,
            (byte)0xbd, (byte)0x9e, 0x10, (byte)0xbb
    };

    // Случай с размером списка менее 16 байтов
    public static byte[] plainText = new byte[] {
            0x39, 0x25, (byte)0x84, 0x1d,
            0x02, (byte)0xdc, 0x09, (byte)0xfb,
            (byte)0xdc, 0x11, (byte)0x85, (byte)0x97,
    };

    @Test
    public void testEncryptAndDecrypt128() {
        cipher = CipherImpl.createInstance(key128);
        byte[] cipherText = cipher.encrypt(plainText);
        Assertions.assertArrayEquals(plainText, cipher.decrypt(cipherText));
    }

    @Test
    public void testEncryptAndDecrypt192() {
        cipher = CipherImpl.createInstance(key192);
        byte[] cipherText = cipher.encrypt(plainText);
        Assertions.assertArrayEquals(plainText, cipher.decrypt(cipherText));
    }

    @Test
    public void testEncryptAndDecrypt256() {
        cipher = CipherImpl.createInstance(key256);
        byte[] cipherText = cipher.encrypt(plainText);
        Assertions.assertArrayEquals(plainText, cipher.decrypt(cipherText));
    }

    @Test
    public void testDecryptInvalidCipherText() {

        byte[] cipherText = new byte[] {
          0x00, 0x11, 0x12, 0x13, 0x14, 0x16, 0x19
        };

        cipher = CipherImpl.createInstance(key128);

        Assertions.assertThrows(IllegalArgumentException.class, () -> cipher.decrypt(cipherText));
    }

    @Test
    public void testOnInvalidKey() {
        byte[] invalidKey = new byte[] {
                0x01, 0x03, 0x06, 0x70,
                0x11, 0x32, (byte)0xcc, (byte)0xab
        };

        Assertions.assertThrows(IllegalArgumentException.class,
                () -> CipherImpl.createInstance(invalidKey),
                "Недопустимая длина ключа");
    }

    @Test
    @SneakyThrows
    public void testOnString128() {
        byte[] keyBytes128 = Arrays.copyOfRange(STRING_KEY.getBytes(StandardCharsets.UTF_8), 0, 16);  // Берем первые 128 бит (16 байт) в ключе

        cipher = CipherImpl.createInstance(keyBytes128);

        byte[] encryptedWith128Key = cipher.encrypt(STRING_PLAINTEXT.getBytes(StandardCharsets.UTF_8));
        byte[] decryptedWith128Key = cipher.decrypt(encryptedWith128Key);

        Assertions.assertEquals(STRING_PLAINTEXT, new String(decryptedWith128Key, StandardCharsets.UTF_8));
    }

    @Test
    @SneakyThrows
    public void testOnString192() {

        byte[] keyBytes192 = Arrays.copyOfRange(STRING_KEY.getBytes(StandardCharsets.UTF_8), 0, 24);  // Берем первые 192 бит (24 байта) в ключе

        cipher = CipherImpl.createInstance(keyBytes192);

        byte[] encryptedWith192Key = cipher.encrypt(STRING_PLAINTEXT.getBytes(StandardCharsets.UTF_8));
        byte[] decryptedWith192Key = cipher.decrypt(encryptedWith192Key);

        Assertions.assertEquals(STRING_PLAINTEXT, new String(decryptedWith192Key, StandardCharsets.UTF_8));
    }

    @Test
    @SneakyThrows
    public void testOnString256() {

        byte[] keyBytes256 = Arrays.copyOfRange(STRING_KEY.getBytes(StandardCharsets.UTF_8), 0, 32);  // Берем первые 256 бит (32 байта) в ключе

        cipher = CipherImpl.createInstance(keyBytes256);

        byte[] encryptedWith256Key = cipher.encrypt(STRING_PLAINTEXT.getBytes(StandardCharsets.UTF_8));
        byte[] decryptedWith256Key = cipher.decrypt(encryptedWith256Key);

        Assertions.assertEquals(STRING_PLAINTEXT, new String(decryptedWith256Key, StandardCharsets.UTF_8));
    }
}
