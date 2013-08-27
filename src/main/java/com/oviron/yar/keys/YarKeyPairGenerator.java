package com.oviron.yar.keys;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Random;

/**
 * A key pair generator.
 *
 * @author Oviron
 */
public class YarKeyPairGenerator {
    private static final int DEFAULT_KEY_LENGTH = 2048;
    private static final int DEFAULT_CERTAINITY = 80;
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger e = BigInteger.valueOf(65537L);
    private static final Random random = new Random();

    /**
     * Generates an RSA keypair with Default key length 2048 bits.
     *
     * @return an RSA keypair.
     */
    public static YarKeyPair generateKeyPair() {
        return generateKeyPair(DEFAULT_KEY_LENGTH);
    }

    /**
     * The algorithm used here is described in NESSIE final report book v0.15
     * https://www.cosic.esat.kuleuven.be/nessie/Bookv015.pdf
     *
     * @param keyLength desired key length in bits.
     * @return an RSA keypair.
     */
    public static YarKeyPair generateKeyPair(int keyLength) {
        if (keyLength < 1024)
            throw new IllegalArgumentException("" + keyLength);

        BigInteger p, q, n;

        int primeLength = (keyLength + 1) / 2;
        do {
            //1. Generate a prime p of length [keyLength/2].
            do {
                p = new BigInteger(primeLength, DEFAULT_CERTAINITY, random);
                //2. Check that GCD(e, p − 1) = 1. If not, goto step 1.
            } while (!p.subtract(ONE).gcd(e).equals(ONE));

            //3. Generate a prime q of length [keyLength/2].
            do {
                q = new BigInteger(primeLength, DEFAULT_CERTAINITY, random);
                //4. Check that q != p. If not, goto step 3.
                //5. Check that and GCD(e, q − 1) = 1. If not, goto step 3.
            } while (q.equals(p) || !q.subtract(ONE).gcd(e).equals(ONE));

            //6. Set n = p*q.
            n = q.multiply(p);
            //7. Check that n has length ln. If not, goto step 1.
        } while (n.bitLength() != keyLength);

        //9. Set d ≡ e^(−1) mod (p − 1)(q − 1).
        BigInteger d = e.modInverse(p.subtract(ONE).multiply(q.subtract(ONE)));

        //10. Output the public key and the secret key.
        RSAPublicKey publicKey = new YarPublicKey(n, e);
        RSAPrivateKey privateKey = new YarPrivateKey(p, q, e, d);

        return new YarKeyPair(publicKey, privateKey);
    }
}