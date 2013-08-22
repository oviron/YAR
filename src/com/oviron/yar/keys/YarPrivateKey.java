package com.oviron.yar.keys;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;

import static com.oviron.yar.Util.BA2I;
import static com.oviron.yar.Util.I2BA;

/**
 * @author: Oviron
 */

public class YarPrivateKey extends YarKey implements RSAPrivateKey {
    public YarPrivateKey(BigInteger modulus, BigInteger exponent) {
        super(modulus, exponent);
    }

    public static YarPrivateKey valueOf(byte[] encoded) {
        int i = 0;

        if (encoded[i++] != 0x52
                || encoded[i++] != 0x53
                || encoded[i++] != 0x41
                || encoded[i++] != 0x4b
                )
            throw new IllegalArgumentException();

        int l;
        byte[] buffer;

        BigInteger modulus;
        BigInteger exponent;

        l = BA2I(Arrays.copyOfRange(encoded, i, i + 4));
        i += 4;
        buffer = Arrays.copyOfRange(encoded, i, i + l);
        modulus = new BigInteger(buffer);
        i += l;

        l = BA2I(Arrays.copyOfRange(encoded, i, i + 4));
        i += 4;
        buffer = Arrays.copyOfRange(encoded, i, i + l);
        exponent = new BigInteger(buffer);
        i += l;

        return new YarPrivateKey(modulus, exponent);
    }

    @Override
    public BigInteger getPrivateExponent() {
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
        baos.write(0x4b); //Public (K)ey

        buffer = getModulus().toByteArray();
        l = I2BA(buffer.length);
        baos.write(l, 0, l.length);
        baos.write(buffer, 0, buffer.length);

        buffer = exponent.toByteArray();
        l = I2BA(buffer.length);
        baos.write(l, 0, l.length);
        baos.write(buffer, 0, buffer.length);

        return baos.toByteArray();
    }
}
