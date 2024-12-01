import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.digitalleague.function.PolynomialGF256.multiply;
import static org.digitalleague.function.PolynomialGF256.multiplyWithTables;

public class PolynomialGF256Test {
    @Test
    public void testMultiply() {
        byte a = 0x02; //0b00000010
        byte[] actual = new byte[9];
        byte[] actual2 = new byte[9];
        byte[] arr = new byte[] {0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0F};
        for (int i = 0; i < arr.length; i++) {
            actual[i] = multiply(a, arr[i]);
            actual2[i] = multiplyWithTables(a, arr[i]);
        }
        Assertions.assertArrayEquals(actual, actual2);
    }

    @Test
    public void testAddition() {
        byte a = (byte)0xdb;
        byte b = 0x02;
        byte expectedSum = (byte)0xd4;
        byte expectedProduct = (byte)0xc1;
    }
}
