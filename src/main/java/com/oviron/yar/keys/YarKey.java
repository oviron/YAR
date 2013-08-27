package com.oviron.yar.keys;

import java.math.BigInteger;
import java.security.Key;
import java.security.interfaces.RSAKey;

/**
 * A base abstract class for both public and private RSA keys.
 *
 * @author Oviron
 */
abstract class YarKey implements Key, RSAKey {
    final BigInteger n;
    final BigInteger e;

    YarKey(BigInteger n, BigInteger e) {
        this.n = n;
        this.e = e;
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
        return n;
    }

    public BigInteger getPublicExponent() {
        return e;
    }

    public boolean equals(Object obj) {
        return super.equals(obj)
                || (obj != null
                && obj instanceof RSAKey
                && n.equals(((RSAKey) obj).getModulus()));

    }
}