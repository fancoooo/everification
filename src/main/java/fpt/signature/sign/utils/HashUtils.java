package fpt.signature.sign.utils;

import java.security.*;

public class HashUtils {
    public static byte[] signHash(byte[] hash, PrivateKey prikey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA256WithRSA");
        sig.initSign(prikey);
        sig.update(hash);
        byte[] signatureBytes = sig.sign();
        return signatureBytes;
    }
}
