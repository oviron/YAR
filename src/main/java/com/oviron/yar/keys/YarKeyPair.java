package com.oviron.yar.keys;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Class containing pair of RSA private and public keys.
 *
 * @author Oviron
 */
public class YarKeyPair {
    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;

    public YarKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }
}