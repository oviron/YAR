package com.oviron.yar.keys;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;

/**
 * @author Oviron
 */

public class YarPrivateKey extends YarKey implements RSAPrivateCrtKey {
    private final BigInteger p;
    private final BigInteger q;
    private final BigInteger d;
    private final BigInteger dP;
    private final BigInteger dQ;
    private final BigInteger qInv;

    public YarPrivateKey(BigInteger p, BigInteger q, BigInteger e, BigInteger d) {
        super(q.multiply(p), e);
        this.d = d;
        this.p = p;
        this.q = q;
        this.dP = d.remainder(p.subtract(BigInteger.ONE));
        this.dQ = d.remainder(q.subtract(BigInteger.ONE));
        this.qInv = q.modInverse(p);
    }

    public static YarPrivateKey valueOf(byte[] encoded) {
        int i = 0;

        if (encoded[i++] != 0x52 //R
                || encoded[i++] != 0x53 //S
                || encoded[i++] != 0x41 //A
                || encoded[i++] != 0x4b //Private (K)ey
                )
            throw new IllegalArgumentException();

        int l;
        byte[] buffer;

        BigInteger e;
        BigInteger d;
        BigInteger p;
        BigInteger q;

        //p
        l = ByteBuffer.wrap(Arrays.copyOfRange(encoded, i, i + 4)).getInt();
        i += 4;
        buffer = Arrays.copyOfRange(encoded, i, i + l);
        p = new BigInteger(buffer);
        i += l;

        //q
        l = ByteBuffer.wrap(Arrays.copyOfRange(encoded, i, i + 4)).getInt();
        i += 4;
        buffer = Arrays.copyOfRange(encoded, i, i + l);
        q = new BigInteger(buffer);
        i += l;

        //e
        l = ByteBuffer.wrap(Arrays.copyOfRange(encoded, i, i + 4)).getInt();
        i += 4;
        buffer = Arrays.copyOfRange(encoded, i, i + l);
        e = new BigInteger(buffer);
        i += l;

        //d
        l = ByteBuffer.wrap(Arrays.copyOfRange(encoded, i, i + 4)).getInt();
        i += 4;
        buffer = Arrays.copyOfRange(encoded, i, i + l);
        d = new BigInteger(buffer);
        i += l;

        return new YarPrivateKey(p, q, e, d);
    }

    @Override
    public BigInteger getPrivateExponent() {
        return d;
    }

    @Override
    public BigInteger getPrimeP() {
        return p;
    }

    @Override
    public BigInteger getPrimeQ() {
        return q;
    }

    @Override
    public BigInteger getPrimeExponentP() {
        return dP;
    }

    @Override
    public BigInteger getPrimeExponentQ() {
        return dQ;
    }

    @Override
    public BigInteger getCrtCoefficient() {
        return qInv;
    }

    @Override
    public byte[] getEncoded() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer;
        byte[] l;

        baos.write(0x52); //R
        baos.write(0x53); //S
        baos.write(0x41); //A
        baos.write(0x4b); //Private (K)ey

        //p
        buffer = p.toByteArray();
        l = ByteBuffer.allocate(4).putInt(buffer.length).array();
        baos.write(l, 0, l.length);
        baos.write(buffer, 0, buffer.length);

        //q
        buffer = q.toByteArray();
        l = ByteBuffer.allocate(4).putInt(buffer.length).array();
        baos.write(l, 0, l.length);
        baos.write(buffer, 0, buffer.length);

        //e
        buffer = e.toByteArray();
        l = ByteBuffer.allocate(4).putInt(buffer.length).array();
        baos.write(l, 0, l.length);
        baos.write(buffer, 0, buffer.length);

        //d
        buffer = d.toByteArray();
        l = ByteBuffer.allocate(4).putInt(buffer.length).array();
        baos.write(l, 0, l.length);
        baos.write(buffer, 0, buffer.length);

        return baos.toByteArray();
    }

    public boolean equals(Object obj) {
        if (!super.equals(obj))
            return false;

        if (obj instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey key = (RSAPrivateCrtKey) obj;
            return p.equals(key.getPrimeP())
                    && q.equals(key.getPrimeQ())
                    && e.equals(key.getPublicExponent())
                    && d.equals(key.getPrivateExponent());
        } else if (obj instanceof RSAPrivateKey) {
            RSAPrivateKey key = (RSAPrivateKey) obj;
            return d.equals(key.getPrivateExponent());
        }

        return false;
    }
}