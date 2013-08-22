package com.oviron.yar;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Random;

import static com.oviron.yar.Primitives.*;
import static com.oviron.yar.Util.indexOf;

/**
 * @author: Oviron
 */

public class YAR {
    private static final ByteArrayOutputStream baos = new ByteArrayOutputStream();

    public static byte[] encrypt(String message, RSAPublicKey publicKey) {
        return encrypt(message.getBytes(), publicKey);
    }

    public static byte[] encrypt(byte[] message, RSAPublicKey publicKey) {
        int modLength = (publicKey.getModulus().bitLength() + 7) / 8;

        if (message.length > modLength - 11)
            throw new IllegalArgumentException("Message too long.");

        byte[] padding = generateEncryptionPadding(modLength - message.length - 3);

        baos.reset();
        baos.write(0x00);
        baos.write(0x02);
        baos.write(padding, 0, padding.length);
        baos.write(0x00);
        baos.write(message, 0, message.length);

        byte[] EM = baos.toByteArray();

        BigInteger ciphertext = RSAEP(publicKey, OS2IP(EM));

        return I2OSP(ciphertext, modLength);
    }

    public static byte[] decrypt(byte[] ciphertext, RSAPrivateKey privateKey) {
        int modLength = (privateKey.getModulus().bitLength() + 7) / 8;

        if (ciphertext.length != modLength)
            throw new IllegalArgumentException("Decryption error.");

        BigInteger m;
        try {
            m = RSADP(privateKey, OS2IP(ciphertext));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Decryption error.");
        }

        byte[] EM = I2OSP(m, modLength);

        int delimIndex = indexOf(EM, (byte) 0x00, 2);

        if (EM[0] != 0x00 || EM[1] != 0x02 || delimIndex == -1)
            throw new IllegalArgumentException("Decryption error.");

        return Arrays.copyOfRange(EM, delimIndex + 1, EM.length);
    }

    public static byte[] sign(String message, RSAPrivateKey privateKey, HashMethod hashMethod) {
        return sign(message.getBytes(), privateKey, hashMethod);
    }

    public static byte[] sign(byte[] message, RSAPrivateKey privateKey, HashMethod hashMethod) {
        int modLength = (privateKey.getModulus().bitLength() + 7) / 8;

        byte[] EM;
        try {
            EM = EMSA(message, modLength, hashMethod);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("RSA modulus too short.");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("No such algorithm. Try to use another hash method.");
        }

        BigInteger signature = RSASP(privateKey, OS2IP(EM));

        return I2OSP(signature, modLength);
    }

    public static boolean verify(RSAPublicKey publicKey, String message, byte[] signature, HashMethod hashMethod) {
        return verify(publicKey, message.getBytes(), signature, hashMethod);
    }

    public static boolean verify(RSAPublicKey publicKey, byte[] message, byte[] signature, HashMethod hashMethod) {
        int modLength = (publicKey.getModulus().bitLength() + 7) / 8;

        if (signature.length != modLength)
            return false;

        BigInteger m;
        byte[] EM;
        try {
            m = RSAVP(publicKey, OS2IP(signature));
            EM = I2OSP(m, modLength);
        } catch (IllegalArgumentException e) {
            return false;
        }

        try {
            return Arrays.equals(EM, YAR.EMSA(message, modLength, hashMethod));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("RSA modulus too short");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("No such algorithm. Try to use another hash method.");
        }
    }

    private static byte[] generateEncryptionPadding(int paddingLength) {
        Random random = new Random();
        byte[] padding = new byte[paddingLength];

        int value;
        for (int i = 0; i < paddingLength; i++) {
            do {
                value = random.nextInt(256) - 128;
            } while (value == 0);
            padding[i] = (byte) value;
        }

        return padding;
    }

    private static byte[] EMSA(byte[] message, int modLength, HashMethod hashMethod) throws NoSuchAlgorithmException {
        byte[] hashedMessage = MessageDigest.getInstance(hashMethod.name).digest(message);

        if (hashedMessage.length + hashMethod.prefix.length > modLength - 11)
            throw new IllegalArgumentException("Intended encoded message length too short");

        int paddingLength = modLength - hashedMessage.length - hashMethod.prefix.length - 3;
        byte[] padding = new byte[paddingLength];
        Arrays.fill(padding, (byte) 0xff);

        baos.reset();
        baos.write(0x00);
        baos.write(0x01);
        baos.write(padding, 0, padding.length);
        baos.write(0x00);
        baos.write(hashMethod.prefix, 0, hashMethod.prefix.length);
        baos.write(hashedMessage, 0, hashedMessage.length);

        return baos.toByteArray();
    }
}
