package keystore;

import fpt.signature.sign.utils.ConfigFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;

public class KeystoreFactory {

    private static String keystorePath;
    private static String keystorePass;

    static {
        keystorePath = ConfigFile.pathKeyStore;
        keystorePass =  ConfigFile.passkeySotre;
    }




    private static KeyStore readPKSC12() throws Exception {
        try {
            System.out.println("[DIGITAL-SIGNING] Start read PKSC12 keystore");
            KeyStore ks = KeyStore.getInstance(KeyStoreType.PKSC12);
            FileInputStream ksFIS = new FileInputStream(new File(keystorePath));
            ks.load(ksFIS, keystorePass.toCharArray());
            System.out.println("[DIGITAL-SIGNING] Read PKSC12 keystore successfully");
            return ks;
        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException ex) {
            System.err.println("Can not read PKSC12 keystore with Error: "  + ex.toString());
            throw new Exception("Can not read PKSC12 keystore with Error: "  + ex.toString());
        }
    }

    public static KeyAndCertChain getPrivateKeyAndCertChain()
            throws Exception {
        KeyStore aKeyStore = readPKSC12();
        Enumeration aliasesEnum = aKeyStore.aliases();
        if (aliasesEnum.hasMoreElements()) {
            String alias = (String)aliasesEnum.nextElement();
            System.out.println("Key alias: "+ alias);
            PrivateKey privateKey = (PrivateKey) aKeyStore.getKey(alias, keystorePass.toCharArray());
            java.security.cert.Certificate cert =  aKeyStore.getCertificate(alias);
            Certificate[] certs =  aKeyStore.getCertificateChain(alias);
            KeyAndCertChain result = new KeyAndCertChain();
            result.setmPrivateKey(privateKey);
            result.setmCertificate((java.security.cert.Certificate) cert);
            result.setmCertificateChain((java.security.cert.Certificate[]) certs);
            return result;
        } else {
            throw new KeyStoreException("The keystore is empty!");
        }
    }
}
