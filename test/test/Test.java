package test;

import com.oviron.yar.HashMethod;
import com.oviron.yar.YAR;
import com.oviron.yar.keys.YarKeyPair;
import com.oviron.yar.keys.YarKeysGenerator;
import com.oviron.yar.keys.YarPrivateKey;
import com.oviron.yar.keys.YarPublicKey;

import static java.lang.System.out;

/**
 * @author: Oviron
 */

public class Test {
    public static void main(String[] args) throws Exception {
        YarKeyPair kp = YarKeysGenerator.generateKeyPair();
        String string = "Help the bombardier!";

        YarPublicKey p = kp.getYarPublicKey();
        YarPrivateKey k = kp.getYarPrivateKey();

        p = YarPublicKey.valueOf(p.getEncoded());
        k = YarPrivateKey.valueOf(k.getEncoded());

        out.println("Encryption test:");
        if (string.equals(new String(YAR.decrypt(YAR.encrypt(string, p), k)))) {
            out.println("OK");
        } else {
            out.println("FAIL");
        }
        out.println();

        out.println("Signature test:");
        for (HashMethod method : HashMethod.values()) {
            out.print(method.name + ": ");
            if (YAR.verify(p, string, YAR.sign(string, k, method), method)) {
                out.println("OK");
            } else {
                out.println("FAIL");
            }
        }
        out.println();
    }
}
