package com.oviron.yar;

import java.nio.ByteBuffer;

/**
 * @author: Oviron
 */

public class Util {
    /**
     * Converts an integer to an array of bytes.
     *
     * @param k integer to be converted
     * @return corresponding array of bytes;
     */
    public static byte[] I2BA(int k) {
        return ByteBuffer.allocate(4).putInt(k).array();
    }

    /**
     * Converts a byte array to an integer.
     *
     * @param b byte array to be converted
     * @return corresponding integer
     */
    public static int BA2I(byte[] b) {
        return ByteBuffer.wrap(b).getInt();
    }

    /**
     * Returns the index within given byte array of the first occurrence of the
     * specified element, starting the search at the specified index.
     *
     * @param array     the input array
     * @param element   element to find
     * @param fromIndex the index to start the search from.
     * @return the index of the first occurrence of the element in the array,
     *         that is greater than or equal to fromIndex,
     *         or -1 if the element does not occur.
     */
    public static int indexOf(byte[] array, byte element, int fromIndex) {
        for (int i = fromIndex; i < array.length; i++) {
            if (element == array[i]) {
                return i;
            }
        }

        return -1;
    }
}
