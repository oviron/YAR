package com.oviron.yar.keys;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;

import static com.oviron.yar.Util.BA2I;
import static com.oviron.yar.Util.I2BA;

/**
 * @author: Oviron
 */

public class YarPrivateKey extends YarKey implements RSAPrivateCrtKey {
    private final BigInteger publicExponent;
    private final BigInteger primeP;
    private final BigInteger primeQ;
    private final BigInteger primeExpP;
    private final BigInteger primeExpQ;
    private final BigInteger qInv;

    public YarPrivateKey(BigInteger privateExponent, BigInteger publicExponent, BigInteger primeP, BigInteger primeQ) {
        super(primeP.multiply(primeQ), privateExponent);
        this.publicExponent = publicExponent;
        this.primeP = primeP;
        this.primeQ = primeQ;
        this.primeExpP = privateExponent.remainder(primeP.subtract(BigInteger.ONE));
        this.primeExpQ = privateExponent.remainder(primeQ.subtract(BigInteger.ONE));
        this.qInv = primeQ.modInverse(primeP);
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

        BigInteger publicExponent;
        BigInteger privateExponent;
        BigInteger primeP;
        BigInteger primeQ;

        //privateExponent
        l = BA2I(Arrays.copyOfRange(encoded, i, i + 4));
        i += 4;
        buffer = Arrays.copyOfRange(encoded, i, i + l);
        privateExponent = new BigInteger(buffer);
        i += l;

        //publicExponent
        l = BA2I(Arrays.copyOfRange(encoded, i, i + 4));
        i += 4;
        buffer = Arrays.copyOfRange(encoded, i, i + l);
        publicExponent = new BigInteger(buffer);
        i += l;

        //primeP
        l = BA2I(Arrays.copyOfRange(encoded, i, i + 4));
        i += 4;
        buffer = Arrays.copyOfRange(encoded, i, i + l);
        primeP = new BigInteger(buffer);
        i += l;

        //primeQ
        l = BA2I(Arrays.copyOfRange(encoded, i, i + 4));
        i += 4;
        buffer = Arrays.copyOfRange(encoded, i, i + l);
        primeQ = new BigInteger(buffer);
        i += l;

        return new YarPrivateKey(privateExponent, publicExponent, primeP, primeQ);
    }

    @Override
    public BigInteger getPrivateExponent() {
        return exponent;
    }

    @Override
    public BigInteger getPublicExponent() {
        return publicExponent;
    }

    @Override
    public BigInteger getPrimeP() {
        return primeP;
    }

    @Override
    public BigInteger getPrimeQ() {
        return primeQ;
    }

    @Override
    public BigInteger getPrimeExponentP() {
        return primeExpP;
    }

    @Override
    public BigInteger getPrimeExponentQ() {
        return primeExpQ;
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

        //privateExponent
        buffer = exponent.toByteArray();
        l = I2BA(buffer.length);
        baos.write(l, 0, l.length);
        baos.write(buffer, 0, buffer.length);

        //publicExponent
        buffer = publicExponent.toByteArray();
        l = I2BA(buffer.length);
        baos.write(l, 0, l.length);
        baos.write(buffer, 0, buffer.length);

        //primeP
        buffer = primeP.toByteArray();
        l = I2BA(buffer.length);
        baos.write(l, 0, l.length);
        baos.write(buffer, 0, buffer.length);

        //primeQ
        buffer = primeQ.toByteArray();
        l = I2BA(buffer.length);
        baos.write(l, 0, l.length);
        baos.write(buffer, 0, buffer.length);

        return baos.toByteArray();
    }

    public boolean equals(Object obj) {
        if (obj instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey key = (RSAPrivateCrtKey) obj;

            return getModulus().equals(key.getModulus()) &&
                    exponent.equals(key.getPrivateExponent()) &&
                    publicExponent.equals(key.getPublicExponent()) &&
                    primeP.equals(key.getPrimeP()) &&
                    primeQ.equals(key.getPrimeQ()) &&
                    primeExpP.equals(key.getPrimeExponentP()) &&
                    primeExpQ.equals(key.getPrimeExponentQ()) &&
                    qInv.equals(key.getCrtCoefficient());
        } else if (obj instanceof RSAPrivateKey) {
            RSAPrivateKey key = (RSAPrivateKey) obj;

            return getModulus().equals(key.getModulus()) &&
                    exponent.equals(key.getPrivateExponent());
        }

        return false;
    }
}
