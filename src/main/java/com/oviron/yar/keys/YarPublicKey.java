package com.oviron.yar.keys;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

/**
 * @author Oviron
 */

public class YarPublicKey extends YarKey implements RSAPublicKey {
    public YarPublicKey(BigInteger n, BigInteger e) {
        super(n, e);
    }

    public static YarPublicKey valueOf(byte[] encoded) {
        int i = 0;

        if (encoded[i++] != 0x52 //R
                || encoded[i++] != 0x53 //S
                || encoded[i++] != 0x41 //A
                || encoded[i++] != 0x50 //(P)ublic Key
                )
            throw new IllegalArgumentException();

        int l;
        byte[] buffer;

        BigInteger modulus;
        BigInteger exponent;

        //n
        l = ByteBuffer.wrap(Arrays.copyOfRange(encoded, i, i + 4)).getInt();
        i += 4;
        buffer = Arrays.copyOfRange(encoded, i, i + l);
        modulus = new BigInteger(buffer);
        i += l;

        //e
        l = ByteBuffer.wrap(Arrays.copyOfRange(encoded, i, i + 4)).getInt();
        i += 4;
        buffer = Arrays.copyOfRange(encoded, i, i + l);
        exponent = new BigInteger(buffer);
        i += l;

        return new YarPublicKey(modulus, exponent);
    }

    @Override
    public byte[] getEncoded() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer;
        byte[] l;

        baos.write(0x52); //R
        baos.write(0x53); //S
        baos.write(0x41); //A
        baos.write(0x50); //(P)ublic Key

        //n
        buffer = n.toByteArray();
        l = ByteBuffer.allocate(4).putInt(buffer.length).array();
        baos.write(l, 0, l.length);
        baos.write(buffer, 0, buffer.length);

        //e
        buffer = e.toByteArray();
        l = ByteBuffer.allocate(4).putInt(buffer.length).array();
        baos.write(l, 0, l.length);
        baos.write(buffer, 0, buffer.length);

        return baos.toByteArray();
    }

    public boolean equals(Object obj) {
        return super.equals(obj)
                && obj instanceof RSAPublicKey
                && e.equals(((RSAPublicKey) obj).getPublicExponent());
    }
}