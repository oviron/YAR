import com.oviron.yar.HashMethod;
import com.oviron.yar.YAR;
import com.oviron.yar.keys.YarKeyPair;
import com.oviron.yar.keys.YarKeysGenerator;
import com.oviron.yar.keys.YarPrivateKey;
import com.oviron.yar.keys.YarPublicKey;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * @author: Oviron
 */

public class TestYar {
    String message = "Help the bombardier!";
    YarPrivateKey privateKey;
    YarPublicKey publicKey;

    @Before
    public void setUp() {
        YarKeyPair kp = YarKeysGenerator.generateKeyPair();
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
        Assert.assertEquals(privateKey, YarPrivateKey.valueOf(privateKey.getEncoded()));
        Assert.assertEquals(publicKey, YarPublicKey.valueOf(publicKey.getEncoded()));
    }

    @Test
    public void testEncryption() {
        byte[] encrypted = YAR.encrypt(message, publicKey);
        Assert.assertArrayEquals(message.getBytes(), YAR.decrypt(encrypted, privateKey));
    }

    @Test
    public void testSignatureMD2() {
        byte[] signature = YAR.sign(message, privateKey, HashMethod.MD2);
        Assert.assertTrue(YAR.verify(publicKey, message, signature, HashMethod.MD2));
    }

    @Test
    public void testSignatureMD5() {
        byte[] signature = YAR.sign(message, privateKey, HashMethod.MD5);
        Assert.assertTrue(YAR.verify(publicKey, message, signature, HashMethod.MD5));
    }

    @Test
    public void testSignatureSHA1() {
        byte[] signature = YAR.sign(message, privateKey, HashMethod.SHA_1);
        Assert.assertTrue(YAR.verify(publicKey, message, signature, HashMethod.SHA_1));
    }

    @Test
    public void testSignatureSHA256() {
        byte[] signature = YAR.sign(message, privateKey, HashMethod.SHA_256);
        Assert.assertTrue(YAR.verify(publicKey, message, signature, HashMethod.SHA_256));
    }

    @Test
    public void testSignatureSHA384() {
        byte[] signature = YAR.sign(message, privateKey, HashMethod.SHA_384);
        Assert.assertTrue(YAR.verify(publicKey, message, signature, HashMethod.SHA_384));
    }

    @Test
    public void testSignatureSHA512() {
        byte[] signature = YAR.sign(message, privateKey, HashMethod.SHA_512);
        Assert.assertTrue(YAR.verify(publicKey, message, signature, HashMethod.SHA_512));
    }
}