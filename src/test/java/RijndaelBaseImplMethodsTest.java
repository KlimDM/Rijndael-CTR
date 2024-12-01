import org.digitalleague.cipher.impl.RijndaelBaseImpl;
import org.digitalleague.cipher.impl.RijndaelBaseImpl.KEY_LENGTH;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;


public class RijndaelBaseImplMethodsTest {
    private final RijndaelBaseImpl cipher = new RijndaelBaseImpl(KEY_LENGTH.KEY_128);
    @Test
    public void testSubBytes() {
        byte[][] state = new byte[][] {
                new byte[] {(byte)0x19, (byte)0xa0, (byte)0x9a, (byte)0xe9},
                new byte[] {(byte)0x3d, (byte)0xf4, (byte)0xc6, (byte)0xf8},
                new byte[] {(byte)0xe3, (byte)0xe2, (byte)0x8d, (byte)0x48},
                new byte[] {(byte)0xbe, (byte)0x2b, (byte)0x2a, (byte)0x08}
        };

        byte[][] expected = new byte[][] {
                new byte[] {(byte)0xd4, (byte)0xe0, (byte)0xb8, (byte)0x1e},
                new byte[] {(byte)0x27, (byte)0xbf, (byte)0xb4, (byte)0x41},
                new byte[] {(byte)0x11, (byte)0x98, (byte)0x5d, (byte)0x52},
                new byte[] {(byte)0xae, (byte)0xf1, (byte)0xe5, (byte)0x30}
        };

        cipher.subBytes(state);
        Assertions.assertArrayEquals(expected, state);

    }

    @Test
    public void testInvSubBytes() {

        byte[][] state = new byte[][] {
                new byte[] {(byte)0xd4, (byte)0xe0, (byte)0xb8, (byte)0x1e},
                new byte[] {(byte)0x27, (byte)0xbf, (byte)0xb4, (byte)0x41},
                new byte[] {(byte)0x11, (byte)0x98, (byte)0x5d, (byte)0x52},
                new byte[] {(byte)0xae, (byte)0xf1, (byte)0xe5, (byte)0x30}
        };

        byte[][] expected = new byte[][] {
                new byte[] {(byte)0x19, (byte)0xa0, (byte)0x9a, (byte)0xe9},
                new byte[] {(byte)0x3d, (byte)0xf4, (byte)0xc6, (byte)0xf8},
                new byte[] {(byte)0xe3, (byte)0xe2, (byte)0x8d, (byte)0x48},
                new byte[] {(byte)0xbe, (byte)0x2b, (byte)0x2a, (byte)0x08}
        };

        cipher.invSubBytes(state);
        Assertions.assertArrayEquals(expected, state);
    }



    @Test
    public void testShiftRows() {

        byte[][] state = new byte[][] {
                new byte[] {(byte)0xd4, (byte)0xe0, (byte)0xb8, (byte)0x1e},
                new byte[] {(byte)0x27, (byte)0xbf, (byte)0xb4, (byte)0x41},
                new byte[] {(byte)0x11, (byte)0x98, (byte)0x5d, (byte)0x52},
                new byte[] {(byte)0xae, (byte)0xf1, (byte)0xe5, (byte)0x30}
        };

        byte[][] expected = new byte[][] {
                new byte[] {(byte)0xd4, (byte)0xe0, (byte)0xb8, (byte)0x1e},
                new byte[] {(byte)0xbf, (byte)0xb4, (byte)0x41, (byte)0x27},
                new byte[] {(byte)0x5d, (byte)0x52, (byte)0x11, (byte)0x98},
                new byte[] {(byte)0x30, (byte)0xae, (byte)0xf1, (byte)0xe5}
        };

        cipher.shiftRows(state);
        Assertions.assertArrayEquals(expected, state);
    }

    @Test
    public void testInvShiftRows() {

        byte[][] state = new byte[][] {
                new byte[] {(byte)0xd4, (byte)0xe0, (byte)0xb8, (byte)0x1e},
                new byte[] {(byte)0xbf, (byte)0xb4, (byte)0x41, (byte)0x27},
                new byte[] {(byte)0x5d, (byte)0x52, (byte)0x11, (byte)0x98},
                new byte[] {(byte)0x30, (byte)0xae, (byte)0xf1, (byte)0xe5}
        };

        byte[][] expected = new byte[][] {
                new byte[] {(byte)0xd4, (byte)0xe0, (byte)0xb8, (byte)0x1e},
                new byte[] {(byte)0x27, (byte)0xbf, (byte)0xb4, (byte)0x41},
                new byte[] {(byte)0x11, (byte)0x98, (byte)0x5d, (byte)0x52},
                new byte[] {(byte)0xae, (byte)0xf1, (byte)0xe5, (byte)0x30}
        };

        cipher.invShiftRows(state);
        Assertions.assertArrayEquals(expected, state);
    }

    @Test
    public void testMixedColumns() {

        byte[][] state = new byte[][] {
                new byte[] {(byte)0xd4, (byte)0xe0, (byte)0xb8, (byte)0x1e},
                new byte[] {(byte)0xbf, (byte)0xb4, (byte)0x41, (byte)0x27},
                new byte[] {(byte)0x5d, (byte)0x52, (byte)0x11, (byte)0x98},
                new byte[] {(byte)0x30, (byte)0xae, (byte)0xf1, (byte)0xe5}
        };

        byte[][] expected = new byte[][] {
                new byte[] {(byte)0x04, (byte)0xe0, (byte)0x48, (byte)0x28},
                new byte[] {(byte)0x66, (byte)0xcb, (byte)0xf8, (byte)0x06},
                new byte[] {(byte)0x81, (byte)0x19, (byte)0xd3, (byte)0x26},
                new byte[] {(byte)0xe5, (byte)0x9a, (byte)0x7a, (byte)0x4c}
        };

        cipher.mixColumns(state);
        Assertions.assertArrayEquals(expected, state);
    }

    @Test
    public void testInvMixedColumns() {

        byte[][] state = new byte[][] {
                new byte[] {(byte)0x04, (byte)0xe0, (byte)0x48, (byte)0x28},
                new byte[] {(byte)0x66, (byte)0xcb, (byte)0xf8, (byte)0x06},
                new byte[] {(byte)0x81, (byte)0x19, (byte)0xd3, (byte)0x26},
                new byte[] {(byte)0xe5, (byte)0x9a, (byte)0x7a, (byte)0x4c}
        };

        byte[][] expected = new byte[][] {
                new byte[] {(byte)0xd4, (byte)0xe0, (byte)0xb8, (byte)0x1e},
                new byte[] {(byte)0xbf, (byte)0xb4, (byte)0x41, (byte)0x27},
                new byte[] {(byte)0x5d, (byte)0x52, (byte)0x11, (byte)0x98},
                new byte[] {(byte)0x30, (byte)0xae, (byte)0xf1, (byte)0xe5}
        };

        cipher.invMixColumns(state);
        Assertions.assertArrayEquals(expected, state);
    }
}
