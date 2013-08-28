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

/**
 * Main library class, containing all encryption and signature methods
 *
 * @author Oviron
 */
public class Yar {
    private static final ByteArrayOutputStream baos = new ByteArrayOutputStream();

    public static byte[] encrypt(String message, RSAPublicKey publicKey) {
        return encrypt(message.getBytes(), publicKey);
    }

    /**
     * RSAES-PKCS1-V1_5-ENCRYPT implementation
     *
     * @param message   message to be encrypted, an octet sequence of length mLen,
     *                  where mLen <= (k – 11)
     * @param publicKey recipient’s RSA public key (k denotes the length in octets
     *                  of the modulus n)
     * @return ciphertext, an octet sequence of length k
     */
    public static byte[] encrypt(byte[] message, RSAPublicKey publicKey) {
        int k = (publicKey.getModulus().bitLength() + 7) / 8;

        //1. Length checking: If mLen > k – 11, output “message too long” and stop.
        if (message.length > k - 11)
            throw new IllegalArgumentException("Message too long.");

        //2. EME-PKCS1-v1_5 encoding:
        //a. Generate an octet sequence PS of length k – mLen – 3 consisting of pseudorandomly
        //generated nonzero octets.
        byte[] PS = generateEncryptionPadding(k - message.length - 3);

        //b. Concatenate PS, the message M, and other padding to form an encoded
        //message EM of length k octets as
        //        EM = 0x00 || 0x02 || PS || 0x00 || M
        baos.reset();
        baos.write(0x00);
        baos.write(0x02);
        baos.write(PS, 0, PS.length);
        baos.write(0x00);
        baos.write(message, 0, message.length);

        byte[] EM = baos.toByteArray();

        //3. RSA encryption:
        //a. Convert the encoded message EM to an integer message representative m.
        //b. Apply the RSAEP encryption primitive to the RSA public key and
        //the message representative m to produce an integer ciphertext representative c.
        BigInteger c = RSAEP(publicKey, OS2IP(EM));

        //c. Convert the ciphertext representative c to a ciphertext C of length k octets.
        //4. Output the ciphertext C.
        return I2OSP(c, k);
    }

    /**
     * RSAES-PKCS1-V1_5-DECRYPT implementation
     *
     * @param ciphertext ciphertext to be decrypted, an octet sequence of length k, where k is
     *                   the length in octets of the RSA modulus n
     * @param privateKey recipient’s RSA private key
     * @return message, an octet sequence of length at most k – 11
     */
    public static byte[] decrypt(byte[] ciphertext, RSAPrivateKey privateKey) {
        int k = (privateKey.getModulus().bitLength() + 7) / 8;

        //1. Length checking: If the length of the ciphertext C is not k octets (or if k < 11),
        //output “decryption error” and stop.
        if (ciphertext.length != k || k < 11)
            throw new IllegalArgumentException("Decryption error.");

        //2. RSA decryption:
        //a. Convert the ciphertext C to an integer ciphertext representative c.
        //b. Apply the RSADP decryption primitive to the RSA private key and the
        //ciphertext representative c to produce an integer message representative m.
        BigInteger m;
        try {
            m = RSADP(privateKey, OS2IP(ciphertext));
        } catch (IllegalArgumentException e) {
            //If RSADP outputs “ciphertext representative out of range” (meaning that c >= n),
            // output “decryption error” and stop.
            throw new IllegalArgumentException("Decryption error.");
        }

        //c. Convert the message representative m to an encoded message EM of length k octets.
        byte[] EM = I2OSP(m, k);

        //3. EME-PKCS1-v1_5 decoding: Separate the encoded message EM into an octet
        //string PS consisting of nonzero octets and a message M as
        //        EM = 0x00 || 0x02 || PS || 0x00 || M
        int delimIndex = -1;
        for (int i = 2; i < EM.length; i++) {
            if (EM[i] == 0x00) {
                delimIndex = i;
            }
        }

        //If the first octet of EM does not have hexadecimal value 0x00, if the second octet
        //of EM does not have hexadecimal value 0x02, if there is no octet with
        //hexadecimal value 0x00 to separate PS from M, or if the length of PS is less than
        //8 octets, output “decryption error” and stop.
        if (EM[0] != 0x00 || EM[1] != 0x02 || delimIndex == -1 || delimIndex < 10)
            throw new IllegalArgumentException("Decryption error.");

        //4. Output M.
        return Arrays.copyOfRange(EM, delimIndex + 1, EM.length);
    }

    public static byte[] sign(String message, RSAPrivateKey privateKey, HashMethod hashMethod) {
        return sign(message.getBytes(), privateKey, hashMethod);
    }

    /**
     * RSASSA-PKCS1-V1_5-SIGN implementation
     *
     * @param message    message to be signed, an octet sequence
     * @param privateKey signer’s RSA private key
     * @param hashMethod specific hash function
     * @return signature, an octet sequence of length k,
     *         where k is the length in octets of the RSA modulus n
     */
    public static byte[] sign(byte[] message, RSAPrivateKey privateKey, HashMethod hashMethod) {
        int k = (privateKey.getModulus().bitLength() + 7) / 8;

        //1. EMSA-PKCS1-v1_5 encoding: Apply the EMSA-PKCS1-v1_5 encoding operation
        //to the message M to produce an encoded message EM of length k octets.
        byte[] EM;
        try {
            EM = EMSA(message, k, hashMethod);
        } catch (IllegalArgumentException e) {
            //If the encoding operation outputs “intended encoded message length too short”,
            //output “RSA modulus too short” and stop.
            throw new IllegalArgumentException("RSA modulus too short.");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("No such algorithm. Try to use another hash method.");
        }

        //2. RSA signature:
        //a. Convert the encoded message EM to an integer message representative m.
        //b. Apply the RSASP1 signature primitive to the RSA private key and
        //the message representative m to produce an integer signature representative s.
        BigInteger m = RSASP1(privateKey, OS2IP(EM));

        //c. Convert the signature representative s to a signature S of length k octets.
        //3. Output the signature S.
        return I2OSP(m, k);
    }

    public static boolean verify(String message, byte[] signature, RSAPublicKey publicKey, HashMethod hashMethod) {
        return verify(message.getBytes(), signature, publicKey, hashMethod);
    }

    /**
     * RSASSA-PKCS1-V1_5-VERIFY implementation
     *
     * @param message    message whose signature is to be verified, an octet sequence
     * @param signature  signature to be verified, an octet sequence of length k, where k is the
     *                   length in octets of the RSA modulus n
     * @param publicKey  signer’s RSA public key
     * @param hashMethod specific hash function
     * @return signature authenticity
     */
    public static boolean verify(byte[] message, byte[] signature, RSAPublicKey publicKey, HashMethod hashMethod) {
        int k = (publicKey.getModulus().bitLength() + 7) / 8;

        //1. Length checking: If the length of the signature S is not k octets,
        //output “invalid signature” and stop.
        if (signature.length != k)
            return false;

        //2. RSA verification:
        //a. Convert the signature S to an integer signature representative s.
        //b. Apply the RSAVP1 verification primitive to the RSA public key
        //and the signature representative s to produce an integer message representative m.
        //c. Convert the message representative m to an encoded message EM of length k octets.
        BigInteger m;
        byte[] EM;
        try {
            m = RSAVP1(publicKey, OS2IP(signature));
            EM = I2OSP(m, k);
        } catch (IllegalArgumentException e) {
            //If RSAVP1 outputs “signature representative out of range,” output
            //“invalid signature” and stop.
            //If I2OSP outputs “integer too large,” output “invalid signature” and stop.
            return false;
        }

        //3. EMSA-PKCS1-v1_5 encoding: Apply the EMSA-PKCS1-v1_5 encoding operation
        //to the message M to produce a second encoded message EM' of length k octets.
        //4. Compare the encoded message EM and the second encoded message EM’. If they
        //are the same, output “valid signature”; otherwise, output “invalid signature.”
        try {
            return Arrays.equals(EM, Yar.EMSA(message, k, hashMethod));
        } catch (IllegalArgumentException e) {
            //If the encoding operation outputs “intended encoded message length too
            //short,” output “RSA modulus too short” and stop.
            throw new IllegalArgumentException("RSA modulus too short");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("No such algorithm. Try to use another hash method.");
        }
    }

    /**
     * Generate an octet sequence consisting of pseudorandomly generated nonzero octets.
     *
     * @param paddingLength length of the resulting octet sequence
     * @return octet sequence of length paddingLength
     */
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

    /**
     * EMSA-PKCS1-v1_5-ENCODE implementation
     *
     * @param message    message to be encoded
     * @param emLen      intended length in octets of the encoded message, at least tLen +
     *                   11, where tLen is the octet length of the DER encoding T of a
     *                   certain value computed during the encoding operation
     * @param hashMethod hash function
     * @return encoded message, an octet sequence of length emLen
     * @throws NoSuchAlgorithmException
     */
    private static byte[] EMSA(byte[] message, int emLen, HashMethod hashMethod) throws NoSuchAlgorithmException {
        //1. Apply the hash function to the message M to produce a hash value hashedMessage:
        byte[] H = MessageDigest.getInstance(hashMethod.name).digest(message);

        //2. Encode the algorithm ID for the hash function and the hash value into an ASN.1
        //value of type DigestInfo with the Distinguished Encoding Rules (DER),
        //where the type DigestInfo has the syntax
        //
        //DigestInfo ::= SEQUENCE {
        //    digestAlgorithm AlgorithmIdentifier,
        //    digest OCTET STRING
        //}
        //
        //The first field identifies the hash function and the second contains the hash value.
        //Let T be the DER encoding of the DigestInfo value (see the notes below) and let
        //tLen be the length in octets of T.

        baos.reset();
        baos.write(hashMethod.prefix, 0, hashMethod.prefix.length);
        baos.write(H, 0, H.length);

        byte[] T = baos.toByteArray();

        //3. If emLen < (tLen + 11), output “intended encoded message length too short” and stop.
        if (emLen < T.length + 11)
            throw new IllegalArgumentException("Intended encoded message length too short");

        //4. Generate an octet string PS consisting of (emLen – tLen – 3) octets with
        //hexadecimal value 0xff. The length of PS will be at least 8 octets.
        byte[] PS = new byte[emLen - T.length - 3];
        Arrays.fill(PS, (byte) 0xff);

        //5. Concatenate PS, the DER encoding T, and other padding to form the encoded
        //message EM as
        //        EM = 0x00 || 0x01 || PS || 0x00 || T
        baos.reset();
        baos.write(0x00);
        baos.write(0x01);
        baos.write(PS, 0, PS.length);
        baos.write(0x00);
        baos.write(T, 0, T.length);

        //6. Output EM.
        return baos.toByteArray();
    }
}