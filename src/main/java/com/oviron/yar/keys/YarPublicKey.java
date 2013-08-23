package com.oviron.yar.keys;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import static com.oviron.yar.Util.BA2I;
import static com.oviron.yar.Util.I2BA;

/**
 * @author: Oviron
 */

public class YarPublicKey extends YarKey implements RSAPublicKey {
    public YarPublicKey(BigInteger modulus, BigInteger exponent) {
        super(modulus, exponent);
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

        //modulus
        l = BA2I(Arrays.copyOfRange(encoded, i, i + 4));
        i += 4;
        buffer = Arrays.copyOfRange(encoded, i, i + l);
        modulus = new BigInteger(buffer);
        i += l;

        //exponent
        l = BA2I(Arrays.copyOfRange(encoded, i, i + 4));
        i += 4;
        buffer = Arrays.copyOfRange(encoded, i, i + l);
        exponent = new BigInteger(buffer);
        i += l;

        return new YarPublicKey(modulus, exponent);
    }

    @Override
    public BigInteger getPublicExponent() {
        return exponent;
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

        //modulus
        buffer = getModulus().toByteArray();
        l = I2BA(buffer.length);
        baos.write(l, 0, l.length);
        baos.write(buffer, 0, buffer.length);

        //exponent
        buffer = exponent.toByteArray();
        l = I2BA(buffer.length);
        baos.write(l, 0, l.length);
        baos.write(buffer, 0, buffer.length);

        return baos.toByteArray();
    }

    public boolean equals(Object obj) {
        if (obj instanceof RSAPublicKey) {
            RSAPublicKey key = (RSAPublicKey) obj;

            return getPublicExponent().equals(key.getPublicExponent()) && getModulus().equals(key.getModulus());
        }

        return false;
    }
}
