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

    public static byte[] hashData(byte[] data, String algorithm) {
        byte[] result = null;
        try {
            if (algorithm.compareToIgnoreCase("MD5") == 0) {
                algorithm = "MD5";
            } else if (algorithm.compareToIgnoreCase("SHA-1") == 0 || algorithm
                    .compareToIgnoreCase("SHA1") == 0) {
                algorithm = "SHA-1";
            } else if (algorithm.compareToIgnoreCase("SHA-256") == 0 || algorithm
                    .compareToIgnoreCase("SHA256") == 0) {
                algorithm = "SHA-256";
            } else if (algorithm.compareToIgnoreCase("SHA-384") == 0 || algorithm
                    .compareToIgnoreCase("SHA384") == 0) {
                algorithm = "SHA-384";
            } else if (algorithm.compareToIgnoreCase("SHA-512") == 0 || algorithm
                    .compareToIgnoreCase("SHA512") == 0) {
                algorithm = "SHA-512";
            } else {
                algorithm = "SHA-256";
            }
            MessageDigest md = MessageDigest.getInstance(algorithm);
            md.update(data);
            result = md.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return result;
    }
}
