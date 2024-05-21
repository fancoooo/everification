package fpt.signature.sign.core;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

public class KeyStoreManager {
    private static final Logger LOG = LoggerFactory.getLogger(KeyStoreManager.class);
    public static final String HARDCODE_SYSTEM_KEY_ENCODED = "ovXifCSpD7gMDQKhVlALaP0WxkcjhKjj56d+f598OlM=";
    public static final String HARDCODE_SYSTEM_IV = "kdAmhbbeM+nIaUwnKTV+Ow==";
    public static final String HARDCODE_SOFTKEY_WRAPPED = "SOFTKEY_WRAPPED";
    public static final String HARDCODE_HSMKEY_WRAPPED = "HSMKEY_WRAPPED";


    public KeyPair generate(String keyAlgorithm, int keySize) throws Exception {
        LOG.debug("Generating AsymmetricKey (keyAlgorithm/keySize): " + keyAlgorithm + "/" + keySize);
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(keyAlgorithm);
        keyGen.initialize(keySize, new SecureRandom());
        KeyPair pair = keyGen.generateKeyPair();
        return pair;
    }

    public SecretKey generateSymmetricKey(String keyMechanism, int keySize) throws NoSuchAlgorithmException {
        LOG.debug("Generating SymmetricKey (keyMechanism/keySize): " + keyMechanism + "/" + keySize);
        KeyGenerator generator = KeyGenerator.getInstance(keyMechanism);
        generator.init(keySize);
        return generator.generateKey();
    }

}

