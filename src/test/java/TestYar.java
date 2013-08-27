import com.oviron.yar.HashMethod;
import com.oviron.yar.Yar;
import com.oviron.yar.keys.YarKeyPair;
import com.oviron.yar.keys.YarKeyPairGenerator;
import com.oviron.yar.keys.YarPrivateKey;
import com.oviron.yar.keys.YarPublicKey;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author Oviron
 */

public class TestYar {
    private final String message = "Help the bombardier!";
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    @Before
    public void setUp() {
        YarKeyPair kp = YarKeyPairGenerator.generateKeyPair();
        privateKey = kp.getPrivateKey();
        publicKey = kp.getPublicKey();
    }

    @After
    public void tearDown() {
        privateKey = null;
        publicKey = null;
    }

    @Test
    public void testKeysEncoding() {
        Assert.assertEquals(publicKey, YarPublicKey.valueOf(publicKey.getEncoded()));
        Assert.assertEquals(privateKey, YarPrivateKey.valueOf(privateKey.getEncoded()));
    }

    @Test
    public void testEncryption() {
        byte[] encrypted = Yar.encrypt(message, publicKey);
        Assert.assertArrayEquals(message.getBytes(), Yar.decrypt(encrypted, privateKey));
    }

    @Test
    public void testSignatureMD2() {
        byte[] signature = Yar.sign(message, privateKey, HashMethod.MD2);
        Assert.assertTrue(Yar.verify(publicKey, message, signature, HashMethod.MD2));
    }

    @Test
    public void testSignatureMD5() {
        byte[] signature = Yar.sign(message, privateKey, HashMethod.MD5);
        Assert.assertTrue(Yar.verify(publicKey, message, signature, HashMethod.MD5));
    }

    @Test
    public void testSignatureSHA1() {
        byte[] signature = Yar.sign(message, privateKey, HashMethod.SHA_1);
        Assert.assertTrue(Yar.verify(publicKey, message, signature, HashMethod.SHA_1));
    }

    @Test
    public void testSignatureSHA256() {
        byte[] signature = Yar.sign(message, privateKey, HashMethod.SHA_256);
        Assert.assertTrue(Yar.verify(publicKey, message, signature, HashMethod.SHA_256));
    }

    @Test
    public void testSignatureSHA384() {
        byte[] signature = Yar.sign(message, privateKey, HashMethod.SHA_384);
        Assert.assertTrue(Yar.verify(publicKey, message, signature, HashMethod.SHA_384));
    }

    @Test
    public void testSignatureSHA512() {
        byte[] signature = Yar.sign(message, privateKey, HashMethod.SHA_512);
        Assert.assertTrue(Yar.verify(publicKey, message, signature, HashMethod.SHA_512));
    }
}