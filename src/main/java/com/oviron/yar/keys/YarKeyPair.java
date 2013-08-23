package com.oviron.yar.keys;

import java.math.BigInteger;

/**
 * @author: Oviron
 */

public class YarKeyPair {
    private final YarPublicKey yarPublicKey;
    private final YarPrivateKey yarPrivateKey;

    public YarKeyPair(BigInteger n, BigInteger d, BigInteger e, BigInteger p, BigInteger q) {
        yarPublicKey = new YarPublicKey(n, e);
        yarPrivateKey = new YarPrivateKey(d, e, p, q);
    }

    public YarPrivateKey getPrivateKey() {
        return yarPrivateKey;
    }

    public YarPublicKey getPublicKey() {
        return yarPublicKey;
    }
}
