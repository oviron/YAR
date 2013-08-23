package com.oviron.yar.keys;

import java.math.BigInteger;
import java.security.Key;
import java.security.interfaces.RSAKey;

/**
 * @author: Oviron
 */

abstract class YarKey implements Key, RSAKey {
    private final BigInteger modulus;
    protected final BigInteger exponent;

    YarKey(BigInteger modulus, BigInteger exponent) {
        this.modulus = modulus;
        this.exponent = exponent;
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public BigInteger getModulus() {
        return modulus;
    }
}