package com.oviron.yar;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Set of cryptographic and data conversion primitives,
 * used in RSA signature and encryption schemes.
 * <p/>
 * The primitives used here are described in
 * PKCS #1 v2.1: RSA Cryptography Standard
 * ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf
 *
 * @author Oviron
 */
class Primitives {
    /**
     * RSA Encryption primitive.
     *
     * @param publicKey RSA Public key
     * @param m         message representative, an integer between 0 and (modulus – 1)
     * @return ciphertext representative, an integer between 0 and (modulus – 1)
     */
    public static BigInteger RSAEP(RSAPublicKey publicKey, BigInteger m) {
        //1. If the message representative m is not between 0 and n – 1, output
        // “message representative out of range” and stop.
        if (m.compareTo(BigInteger.ZERO) < 0 || m.compareTo(publicKey.getModulus().subtract(BigInteger.ONE)) > 0) {
            throw new IllegalArgumentException("Message representative out of range");
        }

        //2. Let c = me mod n.
        //3. Output c.
        return m.modPow(publicKey.getPublicExponent(), publicKey.getModulus());
    }

    /**
     * RSA Decryption primitive.
     *
     * @param privateKey RSA Private key
     * @param c          ciphertext representative, an integer between 0 and (modulus – 1)
     * @return message representative, an integer between 0 and (modulus – 1)
     */
    public static BigInteger RSADP(RSAPrivateKey privateKey, BigInteger c) {
        //1. If the ciphertext representative c is not between 0 and n – 1, output
        // “ciphertext representative out of range” and stop.
        if (c.compareTo(BigInteger.ZERO) < 0 || c.compareTo(privateKey.getModulus().subtract(BigInteger.ONE)) > 0) {
            throw new IllegalArgumentException("Ciphertext representative out of range");
        }

        //a. If the second form (p, q, dP, dQ, qInv) and (ri, di, ti) of K is used, proceed as follows:
        if (privateKey instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey pk = (RSAPrivateCrtKey) privateKey;
            //Let m1 = c^dP mod p and m2 = c^dQ mod q.
            BigInteger m1 = c.modPow(pk.getPrimeExponentP(), pk.getPrimeP());
            BigInteger m2 = c.modPow(pk.getPrimeExponentQ(), pk.getPrimeQ());
            //Let h = (m1 – m2) · qInv mod p.
            BigInteger h = m1.subtract(m2).multiply(pk.getCrtCoefficient()).mod(pk.getPrimeP());
            //Let m = m2 + q · h.
            //Output m.
            return m2.add(h.multiply(pk.getPrimeQ()));
        }

        //b. If the first form (n, d) of K is used, let m = c^d mod n.
        //Output m.
        return c.modPow(privateKey.getPrivateExponent(), privateKey.getModulus());
    }

    /**
     * RSA Signature primitive.
     * Same as RSADP except for the names of input and output arguments.
     * They are distinguished as they are intended for different purposes.
     *
     * @param privateKey RSA Private key
     * @param m          message representative, an integer between 0 and (modulus – 1)
     * @return signature representative, an integer between 0 and (modulus – 1)
     */
    public static BigInteger RSASP1(RSAPrivateKey privateKey, BigInteger m) {
        return RSADP(privateKey, m);
    }

    /**
     * RSA Verification primitive.
     * Same as RSAEP except for the names of input and output arguments.
     * They are distinguished as they are intended for different purposes.
     *
     * @param publicKey RSA Public key
     * @param s         signature representative, an integer between 0 and (modulus – 1)
     * @return message representative, an integer between 0 and (modulus – 1)
     */
    public static BigInteger RSAVP1(RSAPublicKey publicKey, BigInteger s) {
        return RSAEP(publicKey, s);
    }

    /**
     * Integer to Octet Sequence conversion primitive.
     * Converts a nonnegative integer to an octet sequence of a specified length.
     *
     * @param s nonnegative integer to be converted
     * @param k intended length of the resulting octet string
     * @return corresponding octet sequence of length k
     */
    public static byte[] I2OSP(BigInteger s, int k) {
        byte[] result = s.toByteArray();

        if (result.length < k) {
            byte[] b = new byte[k];
            System.arraycopy(result, 0, b, k - result.length, result.length);
            result = b;
        } else if (result.length > k) {
            for (int i = 0; i < result.length - k; i++)
                if (result[i] != 0x00)
                    throw new IllegalArgumentException("Integer too large");
            byte[] b = new byte[k];
            System.arraycopy(result, result.length - k, b, 0, k);
            result = b;
        }

        return result;
    }

    /**
     * Octet Sequence to Integer conversion primitive.
     * Converts an octet sequence to a nonnegative integer.
     *
     * @param s octet sequence to be converted
     * @return corresponding nonnegative integer
     */
    public static BigInteger OS2IP(byte[] s) {
        return new BigInteger(1, s);
    }
}