package com.oviron.yar.keys;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

/**
 * @author: Oviron
 */

public class YarKeysGenerator {
    private static final int DEFAULT_KEY_LENGTH = 2048;

    public static YarKeyPair generateKeyPair() {
        return generateKeyPair(DEFAULT_KEY_LENGTH);
    }

    public static YarKeyPair generateKeyPair(int keyLength) {
        FutureTask<BigInteger> computeP = new FutureTask<>(new PrimeNumComputation(keyLength / 2));

        new Thread(computeP).start();

        BigInteger p;
        BigInteger q = new PrimeNumComputation(keyLength - (keyLength / 2)).compute();

        try {
            p = computeP.get();
        } catch (InterruptedException | ExecutionException e) {
            p = new PrimeNumComputation(keyLength / 2).compute();
        }

        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger n = p.multiply(q);

        BigInteger e = BigInteger.valueOf(65537);
        BigInteger d = e.modInverse(phi);

        return new YarKeyPair(n, d, e, p, q);
    }

    private static class PrimeNumComputation implements Callable<BigInteger> {
        private static final SecureRandom secureRandom = new SecureRandom();
        private final int bitLength;

        public PrimeNumComputation(int bitLength) {
            this.bitLength = bitLength;
        }

        @Override
        public BigInteger call() throws Exception {
            return compute();
        }

        public BigInteger compute() {
            return new BigInteger(bitLength, 100, secureRandom);
        }
    }
}