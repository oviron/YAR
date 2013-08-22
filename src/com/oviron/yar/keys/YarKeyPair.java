package com.oviron.yar.keys;

import java.math.BigInteger;

/**
 * @author: Oviron
 */

public class YarKeyPair {
    private final YarPublicKey yarPublicKey;
    private final YarPrivateKey yarPrivateKey;

    public YarKeyPair(BigInteger n, BigInteger d, BigInteger e) {
        yarPublicKey = new YarPublicKey(n, e);
        yarPrivateKey = new YarPrivateKey(n, d);
    }

    public YarPrivateKey getYarPrivateKey() {
        return yarPrivateKey;
    }

    public YarPublicKey getYarPublicKey() {
        return yarPublicKey;
    }
}
