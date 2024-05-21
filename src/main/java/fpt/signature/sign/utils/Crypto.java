package fpt.signature.sign.utils;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.zip.CRC32;
import java.util.zip.Checksum;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.ejbca.util.CertTools;

public class Crypto {
    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.utils.Crypto.class);

    public static final String HASH_MD5 = "MD5";

    public static final String HASH_SHA1 = "SHA-1";

    public static final String HASH_SHA256 = "SHA-256";

    public static final String HASH_SHA384 = "SHA-384";

    public static final String HASH_SHA512 = "SHA-512";

    public static final String HASH_SHA1_ = "SHA1";

    public static final String HASH_SHA256_ = "SHA256";

    public static final String HASH_SHA384_ = "SHA384";

    public static final String HASH_SHA512_ = "SHA512";

    public static final String SIG_ALO_SHA256_RSA = "SHA256withRSA";

    public static final int HASH_MD5_LEN = 16;

    public static final int HASH_MD5_LEN_PADDED = 34;

    public static final int HASH_SHA1_LEN = 20;

    public static final int HASH_SHA1_LEN_PADDED = 35;

    public static final int HASH_SHA256_LEN = 32;

    public static final int HASH_SHA256_LEN_PADDED = 51;

    public static final int HASH_SHA384_LEN = 48;

    public static final int HASH_SHA384_LEN_PADDED = 67;

    public static final int HASH_SHA512_LEN = 64;

    public static final int HASH_SHA512_LEN_PADDED = 83;

    public static final String KEY_ALGORITHM_RSA = "RSA";

    public static final String KEY_ALGORITHM_DSA = "DSA";

    public static final String CHARSET_UTF8 = "UTF-8";

    public static final String CHARSET_UTF16LE = "UTF-16LE";

    public static final String CHARSET_UTF16BE = "UTF-16BE";

    public static final String BASE64 = "BASE64";

    public static final String SECURE_BLACKBOX_LICENSE = "A6FF3228BE7138FECDEC31C2C99A5AA8F210D38478CD1C257489A48892330D033BF93983DC971DBB8F6665BCB6298984EE82265EE5C4416B7EB7396E33150675C69BF663B9EAE3D2A96D8C523BF1C5A2B4A09D16A8CD905C87A05EE80726DC0491382879DC4E23DF64888841704169E5CDD8157A7A9A782211A31EBA8531406FD3AF310E3AF618070CC280E98EDB522F57C9A8A5A3BE2A60E0B55486512A44B12B014E8B3C499D082D9F84FCD62FA560C29F54513F1B76DC7B92116CE741BD17080040C65F838E4DEE7744F5D7A6257740E8077EFF01C1B57A661AD51C83D94BA962707FFAE0C25EBFDBBDF7DC5A3A92DBD8C60FCED08AF7F874F3A02805C3D7";

    static {
        Security.addProvider((Provider)new BouncyCastleProvider());
    }

    public static long crc32(String data) {
        byte[] bytes = data.getBytes();
        Checksum checksum = new CRC32();
        checksum.update(bytes, 0, bytes.length);
        long checksumValue = checksum.getValue();
        return checksumValue;
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

                LOG.error("No Such Algorithm Exception. Details: " + Utils.printStackTrace(e));
            e.printStackTrace();
        }
        return result;
    }

    public static String hashPass(byte[] data) {
        return DatatypeConverter.printHexBinary(hashData(hashData(data, "SHA-384"), "SHA-384"));
    }

    public static PublicKey getPublicKeyInPemFormat(String data) {
        PublicKey pubKeyString = null;
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(DatatypeConverter.parseBase64Binary(data));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pubKeyString = kf.generatePublic(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return pubKeyString;
    }

    public static PublicKey getPublicKeyInHexFormat(String data) {
        PublicKey pubKeyString = null;
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(DatatypeConverter.parseHexBinary(data));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pubKeyString = kf.generatePublic(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return pubKeyString;
    }

    public static X509Certificate getX509Object(String pem) {
        X509Certificate x509 = null;
        try {
            CertificateFactory certFactoryChild = CertificateFactory.getInstance("X.509", "BC");
            InputStream inChild = new ByteArrayInputStream(getX509Der(pem));
            x509 = (X509Certificate)certFactoryChild.generateCertificate(inChild);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return x509;
    }

    public static byte[] getX509CertificateEncoded(X509Certificate x509) {
        byte[] data = null;
        try {
            data = x509.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();

                LOG.error("Error while getting X509Certificate encoded data. Details: " + Utils.printStackTrace(e));
        }
        return data;
    }

    public static byte[] getPublicKeyEncoded(X509Certificate x509) {
        byte[] data = null;
        try {
            data = x509.getPublicKey().getEncoded();
        } catch (Exception e) {
            e.printStackTrace();

                LOG.error("Error while getting X509Certificate encoded data. Details: " + Utils.printStackTrace(e));
        }
        return data;
    }

    public static int checkCertificateValidity(X509Certificate x509) {
        int status;
        try {
            x509.checkValidity();
            status = 0;
        } catch (CertificateExpiredException e) {
            e.printStackTrace();
            status = 1;
        } catch (CertificateNotYetValidException e) {
            e.printStackTrace();
            status = -1;
        }
        return status;
    }

    private static byte[] getX509Der(String base64Str) throws Exception {
        byte[] binary = null;
        if (base64Str.indexOf("-----BEGIN CERTIFICATE-----") != -1) {
            binary = base64Str.getBytes();
        } else {
            binary = DatatypeConverter.parseBase64Binary(base64Str);
        }
        return binary;
    }

    public static SecretKey computeSecretKey(String keyType, byte[] rawSecretKey) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(rawSecretKey, keyType);
        return secretKeySpec;
    }


    public static PublicKey getPublicKeyFromString(String key) throws Exception {
        byte[] encoded;
        String publicKeyPEM = key;
        publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----\n", "");
        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
        publicKeyPEM = publicKeyPEM.replace("-----BEGIN RSA PUBLIC KEY-----\n", "");
        publicKeyPEM = publicKeyPEM.replace("-----END RSA PUBLIC KEY-----", "");
        publicKeyPEM = publicKeyPEM.replace("\n", "").replace("\r", "");

        encoded = java.util.Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        PublicKey pub = (PublicKey) kf.generatePublic(keySpec);
        return pub;
    }

    public static byte[] wrapSecrectKey(String algWrapping, SecretKey wrappingKey, byte[] wrappingIv, Key keyToBeWrapped) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidParameterSpecException, IllegalBlockSizeException, NoSuchProviderException {
        Cipher wrappingCipher = Cipher.getInstance(algWrapping);
        String[] list = algWrapping.split("/");
        AlgorithmParameters algParams = AlgorithmParameters.getInstance(list[0]);
        algParams.init(new IvParameterSpec(wrappingIv));
        wrappingCipher.init(3, wrappingKey, algParams);
        return wrappingCipher.wrap(keyToBeWrapped);
    }

    public static Key unwrapSecrectKey(String algWrap, String wrappedKeyAlgorithm, SecretKey wrappingKey, byte[] wrappingIv, byte[] wrappedKey, int wrappedKeyType) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidParameterSpecException, IllegalBlockSizeException, NoSuchProviderException {
        Cipher wrappingCipher = Cipher.getInstance(algWrap);
        String[] list = algWrap.split("/");
        AlgorithmParameters algParams = AlgorithmParameters.getInstance(list[0]);
        algParams.init(new IvParameterSpec(wrappingIv));
        wrappingCipher.init(4, wrappingKey, algParams);
        return wrappingCipher.unwrap(wrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
    }

    public static byte[] encrypt(String encryptType, SecretKey key, byte[] initVector, byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        IvParameterSpec iv = new IvParameterSpec(initVector);
        Cipher cipher = Cipher.getInstance(encryptType);
        cipher.init(1, key, iv);
        byte[] encrypted = cipher.doFinal(data);
        return encrypted;
    }

    public static byte[] decrypt(String encryptType, SecretKey key, byte[] initVector, byte[] encoded) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        IvParameterSpec iv = new IvParameterSpec(initVector);
        Cipher cipher = Cipher.getInstance(encryptType);
        cipher.init(2, key, iv);
        byte[] data = cipher.doFinal(encoded);
        return data;
    }

    public static List<Certificate> getCertificateChain(String caCert1, String caCert2, X509Certificate cert) {
        X509Certificate endCert = null;
        X509Certificate ca1 = null;
        X509Certificate ca2 = null;
        endCert = cert;
        ca1 = getX509Object(caCert1);
        try {
            endCert.verify(ca1.getPublicKey());
            Collection<Certificate> certChain = CertTools.getCertsFromPEM(new ByteArrayInputStream(caCert1.getBytes()));
            certChain.add(endCert);
            List<Certificate> certificates = new ArrayList<>(certChain);
            Collections.reverse(certificates);
            return certificates;
        } catch (Exception e) {

                LOG.warn("First CA certificate isn't the one who issues end-user certificate. Try the second one");
            ca2 = getX509Object(caCert2);
            try {
                endCert.verify(ca2.getPublicKey());
                Collection<Certificate> certChain = CertTools.getCertsFromPEM(new ByteArrayInputStream(caCert2.getBytes()));
                certChain.add(endCert);
                List<Certificate> certificates = new ArrayList<>(certChain);
                Collections.reverse(certificates);
                return certificates;
            } catch (Exception exx) {
                exx.printStackTrace();
                return null;
            }
        }
    }

    public static String sign(String data, String keystorePath, String keystorePassword, String keystoreType) throws Exception {
        Signature sig;
        Security.addProvider((Provider)new BouncyCastleProvider());
        KeyStore keystore = KeyStore.getInstance(keystoreType);
        try (InputStream is = new FileInputStream(keystorePath)) {
            keystore.load(is, keystorePassword.toCharArray());
            Enumeration<String> e = keystore.aliases();
            PrivateKey key = null;
            while (e.hasMoreElements()) {
                String aliasName = e.nextElement();
                key = (PrivateKey)keystore.getKey(aliasName, keystorePassword
                        .toCharArray());
                if (key != null)
                    break;
            }
            sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(key);
            sig.update(data.getBytes());
        }
        return DatatypeConverter.printBase64Binary(sig.sign());
    }

    public static String sign(String data, String keystr, String mimeType) throws Exception {
        Security.addProvider((Provider)new BouncyCastleProvider());
        PrivateKey key = getPrivateKeyFromString(keystr, mimeType);
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(key);
        sig.update(data.getBytes());
        return DatatypeConverter.printBase64Binary(sig.sign());
    }

    public static PrivateKey getPrivateKeyFromString(String key) throws Exception {
        byte[] encoded;
        String privateKeyPEM = key;
        privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----\n", "");
        privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
        privateKeyPEM = privateKeyPEM.replace("-----BEGIN RSA PRIVATE KEY-----\n", "");
        privateKeyPEM = privateKeyPEM.replace("-----END RSA PRIVATE KEY-----", "");
        privateKeyPEM = privateKeyPEM.replace("\n", "").replace("\r", "");

        encoded = java.util.Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        PrivateKey privKey = (PrivateKey) kf.generatePrivate(keySpec);
        return privKey;
    }

    public static String convertPemCertificate(String pem) {
        pem = pem.replace("-----BEGIN CERTIFICATE-----\n", "");
        pem = pem.replace("-----END CERTIFICATE-----", "");
        pem = pem.replace("\n", "").replace("\r", "");
        return pem;
    }

    public static PrivateKey getPrivateKeyFromString(String key, String mimeType) throws IOException, GeneralSecurityException {
        byte[] encoded = null;
        if (mimeType.toLowerCase().contains("base64")) {
            String privateKeyPEM = key;
            privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----\n", "");
            privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
            encoded = DatatypeConverter.parseBase64Binary(privateKeyPEM);
        } else {
            encoded = DatatypeConverter.parseHexBinary(key);
        }
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        PrivateKey privKey = kf.generatePrivate(keySpec);
        return privKey;
    }

    public static PrivateKey getPrivateKey(byte[] pk) throws IOException, GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pk);
        PrivateKey privKey = kf.generatePrivate(keySpec);
        return privKey;
    }

    public static boolean[] getKeyUsage(X509Certificate x509) {
        return x509.getKeyUsage();
    }

    public static int getBasicConstraint(X509Certificate x509) {
        return x509.getBasicConstraints();
    }

    public static byte[] padSHA1Oid(byte[] hashedData) throws Exception {
        DERObjectIdentifier sha1oid_ = new DERObjectIdentifier("1.3.14.3.2.26");
        AlgorithmIdentifier sha1aid_ = new AlgorithmIdentifier(sha1oid_, null);
        DigestInfo di = new DigestInfo(sha1aid_, hashedData);
        byte[] plainSig = di.getEncoded("DER");
        return plainSig;
    }

    public static boolean checkCertificateRelation(String childCert, String parentCert) {
        boolean isOk = false;
        try {
            CertificateFactory certFactoryChild = CertificateFactory.getInstance("X.509", "BC");
            InputStream inChild = new ByteArrayInputStream(getX509Der(childCert));
            X509Certificate certChild = (X509Certificate)certFactoryChild.generateCertificate(inChild);
            CertificateFactory certFactoryParent = CertificateFactory.getInstance("X.509", "BC");
            InputStream inParent = new ByteArrayInputStream(getX509Der(parentCert));
            X509Certificate certParent = (X509Certificate)certFactoryParent.generateCertificate(inParent);
            certChild.verify(certParent.getPublicKey());
            isOk = true;
        } catch (SignatureException e) {

                LOG.error("Invalid certficate. Signature exception. Details: " + Utils.printStackTrace(e));
        } catch (CertificateException e) {

                LOG.error("Invalid certficate. Certificate exception. Details: " + Utils.printStackTrace(e));
        } catch (Exception e) {

                LOG.error("Invalid certficate. Something wrong exception. Details: " + Utils.printStackTrace(e));
        }
        return isOk;
    }

    public static boolean checkCertificateRelation(X509Certificate childCert, X509Certificate parentCert) {
        boolean isOk = false;
        try {
            childCert.verify(parentCert.getPublicKey());
            isOk = true;
        } catch (SignatureException e) {

                LOG.error("Invalid certficate. Signature exception. Details: " + Utils.printStackTrace(e));
            e.printStackTrace();
        } catch (CertificateException e) {

                LOG.error("Invalid certficate. Certificate exception. Details: " + Utils.printStackTrace(e));
            e.printStackTrace();
        } catch (Exception e) {

                LOG.error("Invalid certficate. Something wrong exception. Details: " + Utils.printStackTrace(e));
            e.printStackTrace();
        }
        return isOk;
    }

    public static String encryptRSA(String message, PublicKey publicKey) {
        String result = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(1, publicKey);
            result = DatatypeConverter.printBase64Binary(cipher.doFinal(message.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static String decryptRSA(String message, PrivateKey privateKey) {
        String result = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(2, privateKey);
            result = new String(cipher.doFinal(DatatypeConverter.parseBase64Binary(message)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static boolean validateHashData(String hash) {
        if (hash.length() % 2 != 0) {

                LOG.error("Invalid HashData=" + hash + " modulus of 2 should be ZERO");
            return false;
        }
        byte[] binraryHash = DatatypeConverter.parseHexBinary(hash);
        if (binraryHash.length > 83) {

                LOG.error("Hash length is greater than 64 bytes. Wtf?");
            return false;
        }
        return true;
    }

    public static String getHashAlgorithm(byte[] hashData) {
        int len = hashData.length;
        switch (len) {
            case 16:
                return "MD5";
            case 34:
                return "MD5";
            case 20:
                return "SHA-1";
            case 35:
                return "SHA-1";
            case 32:
                return "SHA-256";
            case 51:
                return "SHA-256";
            case 48:
                return "SHA-384";
            case 67:
                return "SHA-384";
            case 64:
                return "SHA-512";
            case 83:
                return "SHA-512";
        }
        return "SHA-1";
    }

    public static byte[] getBytes(String data, String charset) {
        byte[] bytes;
        try {
            bytes = data.getBytes(charset);
        } catch (Exception e) {
            e.printStackTrace();

                LOG.error("Invalid charset " + charset + ". Using the default one. It maybe got the unicode issue. Details: " + Utils.printStackTrace(e));
            bytes = data.getBytes();
        }
        return bytes;
    }

    public static String generatePKCS1Signature(String data, String keyStorePath, String keyStorePassword, String keystoreType) throws Exception {
        Signature sig;
        Security.addProvider((Provider)new BouncyCastleProvider());
        KeyStore keystore = KeyStore.getInstance(keystoreType);
        try (InputStream is = new FileInputStream(keyStorePath)) {
            keystore.load(is, keyStorePassword.toCharArray());
            Enumeration<String> e = keystore.aliases();
            PrivateKey key = null;
            while (e.hasMoreElements()) {
                String aliasName = e.nextElement();
                key = (PrivateKey)keystore.getKey(aliasName, keyStorePassword
                        .toCharArray());
                if (key != null)
                    break;
            }
            sig = Signature.getInstance("SHA1withRSA");
            sig.initSign(key);
            sig.update(data.getBytes());
        }
        return DatatypeConverter.printBase64Binary(sig.sign());
    }

    public static PublicKey computePublicKey(BigInteger modulus, BigInteger exponent) {
        PublicKey pubKey = null;
        try {
            pubKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return pubKey;
    }

    public static byte[] paddingSHA1OID(byte[] hashedData) throws Exception {
        DefaultDigestAlgorithmIdentifierFinder defaultDigestAlgorithmIdentifierFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier hashingAlgorithmIdentifier = defaultDigestAlgorithmIdentifierFinder.find("SHA-1");
        DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, hashedData);
        return digestInfo.getEncoded();
    }

    public static byte[] paddingSHA256OID(byte[] hashedData) throws Exception {
        DefaultDigestAlgorithmIdentifierFinder defaultDigestAlgorithmIdentifierFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier hashingAlgorithmIdentifier = defaultDigestAlgorithmIdentifierFinder.find("SHA-256");
        DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, hashedData);
        return digestInfo.getEncoded();
    }

    public static byte[] paddingSHA384OID(byte[] hashedData) throws Exception {
        DefaultDigestAlgorithmIdentifierFinder defaultDigestAlgorithmIdentifierFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier hashingAlgorithmIdentifier = defaultDigestAlgorithmIdentifierFinder.find("SHA-384");
        DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, hashedData);
        return digestInfo.getEncoded();
    }

    public static byte[] paddingSHA512OID(byte[] hashedData) throws Exception {
        DefaultDigestAlgorithmIdentifierFinder defaultDigestAlgorithmIdentifierFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier hashingAlgorithmIdentifier = defaultDigestAlgorithmIdentifierFinder.find("SHA-512");
        DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, hashedData);
        return digestInfo.getEncoded();
    }

    public static byte[] paddingMD5OID(byte[] hashedData) throws Exception {
        DefaultDigestAlgorithmIdentifierFinder defaultDigestAlgorithmIdentifierFinder = new DefaultDigestAlgorithmIdentifierFinder();
        AlgorithmIdentifier hashingAlgorithmIdentifier = defaultDigestAlgorithmIdentifierFinder.find("MD5");
        DigestInfo digestInfo = new DigestInfo(hashingAlgorithmIdentifier, hashedData);
        return digestInfo.getEncoded();
    }

    public static byte[] generateKeystore(String keyName, byte[] encPubKey, PrivateKey privateKey, String password) throws Exception {
        String subjectDn = "CN=" + keyName;
        X509Certificate selfsignCertificate = generateSelfSignCertificate(subjectDn, encPubKey, privateKey);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null);
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = selfsignCertificate;
        keyStore.setKeyEntry(keyName, privateKey, password.toCharArray(), (Certificate[])chain);
        OutputStream os = new ByteArrayOutputStream();
        keyStore.store(os, password.toCharArray());
        return ((ByteArrayOutputStream)os).toByteArray();
    }

    private static X509Certificate generateSelfSignCertificate(String subjectDN, byte[] encPubKey, PrivateKey privateKey) throws Exception {
        X500Name issuer = new X500Name(subjectDN);
        X500Name subject = new X500Name(subjectDN);
        RDN[] rdns = subject.getRDNs();
        Calendar c = Calendar.getInstance();
        Date validFrom = c.getTime();
        c.add(5, 3650);
        Date validTo = c.getTime();
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, new BigInteger(1, Utils.genRandomArray(16)), validFrom, validTo, subject, SubjectPublicKeyInfo.getInstance(encPubKey));
        GeneralName ocspLocation = new GeneralName(6, "http://mobile-id.vn:81/ejbca/publicweb/status/ocsp");
        certBuilder.addExtension(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.1"), false, (ASN1Encodable)new AuthorityInformationAccess(X509ObjectIdentifiers.ocspAccessMethod, ocspLocation));
        String crls = "https://mobile-id.vn/crl/Mobile-ID.crl";
        StringTokenizer tokenizer = new StringTokenizer(crls, ";", false);
        ArrayList<DistributionPoint> distpoints = new ArrayList();
        while (tokenizer.hasMoreTokens()) {
            String uri = tokenizer.nextToken();
            GeneralName gn = new GeneralName(6, uri);
            ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add((ASN1Encodable)gn);
            GeneralNames gns = GeneralNames.getInstance(new DERSequence(vec));
            DistributionPointName dpn = new DistributionPointName(0, (ASN1Encodable)gns);
            distpoints.add(new DistributionPoint(dpn, null, null));
        }
        if (distpoints.size() > 0) {
            CRLDistPoint ext = new CRLDistPoint(distpoints.<DistributionPoint>toArray(new DistributionPoint[0]));
            certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.31"), true, (ASN1Encodable)ext);
        }
        SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo((ASN1Sequence)(new ASN1InputStream(encPubKey)).readObject());
        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.14"), false, (ASN1Encodable)new SubjectKeyIdentifier(

                hashData(subjectPublicKeyInfo.getPublicKeyData().getBytes(), "SHA-1")));
        SubjectPublicKeyInfo info = new SubjectPublicKeyInfo((ASN1Sequence)(new ASN1InputStream(encPubKey)).readObject());
        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.35"), false, (ASN1Encodable)new AuthorityKeyIdentifier(info));
        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, (ASN1Encodable)new BasicConstraints(false));
        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true, (ASN1Encodable)new KeyUsage(240));
        KeyPurposeId[] keyPurposeId = { KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_emailProtection };
        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true, (ASN1Encodable)new ExtendedKeyUsage(keyPurposeId));
        certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.17"), false, (ASN1Encodable)new GeneralNames(new GeneralName(1, "vudp@mobile-id.vn")));
        JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = builder.build(privateKey);
        byte[] certBytes = certBuilder.build(signer).getEncoded();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));
        return certificate;
    }

    public static String getPKCS1Signature(String data, String relyingPartyKeyStore, String relyingPartyKeyStorePassword) throws Exception {
        Security.addProvider((Provider)new BouncyCastleProvider());
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        InputStream is = new FileInputStream(relyingPartyKeyStore);
        keystore.load(is, relyingPartyKeyStorePassword.toCharArray());
        Enumeration<String> e = keystore.aliases();
        String aliasName = "";
        while (e.hasMoreElements())
            aliasName = e.nextElement();
        PrivateKey key = (PrivateKey)keystore.getKey(aliasName, relyingPartyKeyStorePassword
                .toCharArray());
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(key);
        sig.update(data.getBytes());
        return DatatypeConverter.printBase64Binary(sig.sign());
    }

    public static byte[] md5(byte[] data) {
        byte[] result = null;
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(data);
            result = md.digest();
        } catch (NoSuchAlgorithmException e) {

                LOG.error("No Such Algorithm Exception. Details: " + Utils.printStackTrace(e));
            e.printStackTrace();
        }
        return result;
    }

    public static String getOcspUri1(X509Certificate certificate) {
        String ocspUri = null;
        try {
            ASN1Object obj = getExtensionValue(certificate, Extension.authorityInfoAccess.getId());
            if (obj == null)
                return null;
            ASN1Sequence AccessDescriptions = (ASN1Sequence)obj;
            for (int i = 0; i < AccessDescriptions.size(); i++) {
                ASN1Sequence AccessDescription = (ASN1Sequence)AccessDescriptions.getObjectAt(i);
                if (AccessDescription.size() == 2)
                    if (AccessDescription.getObjectAt(0) instanceof DERObjectIdentifier && ((DERObjectIdentifier)AccessDescription.getObjectAt(0)).getId().equals("1.3.6.1.5.5.7.48.1")) {
                        String AccessLocation = getStringFromGeneralName((ASN1Object)AccessDescription.getObjectAt(1));
                        if (AccessLocation == null)
                            return null;
                        return AccessLocation;
                    }
            }
        } catch (Exception e) {

                LOG.error("Error while getting OCSP URI. Details: " + Utils.printStackTrace(e));
            e.printStackTrace();
        }
        return ocspUri;
    }

    public static List<String> getOcspUris(X509Certificate certificate) {
        List<String> urls = new ArrayList<>();
        try {
            ASN1Object obj = getExtensionValue(certificate, Extension.authorityInfoAccess.getId());
            if (obj == null)
                return null;
            ASN1Sequence AccessDescriptions = (ASN1Sequence)obj;
            for (int i = 0; i < AccessDescriptions.size(); i++) {
                ASN1Sequence AccessDescription = (ASN1Sequence)AccessDescriptions.getObjectAt(i);
                if (AccessDescription.size() == 2)
                    if (AccessDescription.getObjectAt(0) instanceof DERObjectIdentifier && ((DERObjectIdentifier)AccessDescription.getObjectAt(0)).getId().equals("1.3.6.1.5.5.7.48.1")) {
                        String AccessLocation = getStringFromGeneralName((ASN1Object)AccessDescription.getObjectAt(1));
                        if (!Utils.isNullOrEmpty(AccessLocation))
                            urls.add(AccessLocation);
                    }
            }
        } catch (Exception e) {

                LOG.error("Error while getting OCSP URI. Details: " + Utils.printStackTrace(e));
            e.printStackTrace();
            urls = null;
        }
        return urls;
    }

    public static ASN1Object getExtensionValue(X509Certificate cert, String oid) throws IOException {
        byte[] bytes = cert.getExtensionValue(oid);
        if (bytes == null)
            return null;
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
        ASN1OctetString octs = (ASN1OctetString)aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        return (ASN1Object)aIn.readObject();
    }

    private static String getStringFromGeneralName(ASN1Object names) throws IOException {
        DERTaggedObject taggedObject = (DERTaggedObject)names;
        return new String(ASN1OctetString.getInstance((ASN1TaggedObject)taggedObject, false).getOctets(), "ISO-8859-1");
    }

    public static String getSubjectKeyIdentifier(X509Certificate cert) {
        byte[] extensionValue = cert.getExtensionValue("2.5.29.14");
        if (DEROctetString.getInstance(extensionValue) == null) {

                LOG.warn("WARNING!!!. SubjectKeyIdentifier NOT found for DN " + cert.getSubjectDN().toString());
            return "";
        }
        byte[] octets = DEROctetString.getInstance(extensionValue).getOctets();
        SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.getInstance(octets);
        byte[] keyIdentifier = subjectKeyIdentifier.getKeyIdentifier();
        String keyIdentifierHex = DatatypeConverter.printHexBinary(keyIdentifier).toLowerCase();
        return keyIdentifierHex;
    }

    public static String getIssuerKeyIdentifier(X509Certificate cert) {
        byte[] extensionValue = cert.getExtensionValue("2.5.29.35");
        if (DEROctetString.getInstance(extensionValue) == null) {

                LOG.warn("WARNING!!!. IssuerKeyIdentifier NOT found for DN " + cert.getSubjectDN().toString());
            return "";
        }
        byte[] octets = DEROctetString.getInstance(extensionValue).getOctets();
        AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(octets);
        byte[] keyIdentifier = authorityKeyIdentifier.getKeyIdentifier();
        String keyIdentifierHex = DatatypeConverter.printHexBinary(keyIdentifier).toLowerCase();
        return keyIdentifierHex;
    }

    public static String convertToBase64PEMString(Certificate x509Cert) {
        String pem = "";
        try {
            StringWriter sw = new StringWriter();
            try (PEMWriter pw = new PEMWriter(sw)) {
                pw.writeObject(x509Cert);
            }
            return sw.toString();
        } catch (Exception e) {

                LOG.error("Error while converting X509Certificate to Base64 PEM String. Details: " + Utils.printStackTrace(e));
            e.printStackTrace();
            return pem;
        }
    }

    private static byte[] randomBytes(int length) {
        Random randomno = new Random();
        byte[] nbyte = new byte[length];
        randomno.nextBytes(nbyte);
        return nbyte;
    }

    public static String generateAccessKeyID() {
        return Base64.getUrlEncoder().encodeToString(randomBytes(15)).toUpperCase();
    }

    public static String generateXApiKey() {
        return Base64.getUrlEncoder().encodeToString(randomBytes(30));
    }

    public static String generateSecretKey() {
        return Base64.getUrlEncoder().encodeToString(randomBytes(30));
    }

    public static List<String> getCRLDistributionPoints(X509Certificate certificate) {
        byte[] crlDistributionPoint = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (crlDistributionPoint == null)
            return null;
        List<String> crlUrls = new ArrayList<>();
        try {
            CRLDistPoint distPoint = CRLDistPoint.getInstance(JcaX509ExtensionUtils.parseExtensionValue(crlDistributionPoint));
            for (DistributionPoint dp : distPoint.getDistributionPoints()) {
                DistributionPointName dpn = dp.getDistributionPoint();
                if (dpn != null &&
                        dpn.getType() == 0) {
                    GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                    for (int j = 0; j < genNames.length; j++) {
                        if (genNames[j].getTagNo() == 6) {
                            String url = DERIA5String.getInstance(genNames[j].getName()).getString();
                            crlUrls.add(url);
                        }
                    }
                }
            }
        } catch (Exception e) {
            crlUrls = null;
        }
        return crlUrls;
    }

    public static boolean isCACertificate(X509Certificate x509Certificate) {
        if (x509Certificate == null)
            return false;
        boolean[] keyUsages = getKeyUsage(x509Certificate);
        if (keyUsages != null) {
            if (keyUsages[5])
                return true;
            return false;
        }
        int pathLen = x509Certificate.getBasicConstraints();
        if (pathLen != -1)
            return true;
        return false;
    }

    public static boolean isRootCACertificate(X509Certificate x509Certificate) {
        boolean isCA = isCACertificate(x509Certificate);
        if (isCA &&
                x509Certificate.getSubjectDN().equals(x509Certificate.getIssuerDN()))
            return true;
        return false;
    }

    public static List<X509Certificate> sortX509Chain(List<X509Certificate> certs) throws Exception {
        LinkedList<X509Certificate> sortedCerts = new LinkedList<>();
        LinkedList<X509Certificate> unsortedCerts = new LinkedList<>(certs);
        sortedCerts.add(unsortedCerts.pollFirst());
        int escapeCounter = 0;
        while (!unsortedCerts.isEmpty()) {
            int initialSize = unsortedCerts.size();
            X509Certificate currentCert = unsortedCerts.pollFirst();
            if (currentCert.getIssuerX500Principal().equals(((X509Certificate)sortedCerts.peekFirst()).getSubjectX500Principal())) {
                sortedCerts.offerFirst(currentCert);
            } else if (currentCert.getSubjectX500Principal().equals(((X509Certificate)sortedCerts.peekLast()).getIssuerX500Principal())) {
                sortedCerts.offerLast(currentCert);
            } else {
                unsortedCerts.offerLast(currentCert);
            }
            if (unsortedCerts.size() == initialSize) {
                escapeCounter++;
                if (escapeCounter >= 2 * initialSize)
                    throw new Exception();
                continue;
            }
            escapeCounter = 0;
        }
        return sortedCerts;
    }

    public static boolean validateCertificateValidity(X509Certificate x509) {
        try {
            x509.checkValidity();
            return true;
        } catch (CertificateExpiredException certificateExpiredException) {

        } catch (CertificateNotYetValidException certificateNotYetValidException) {}
        return false;
    }

    public static byte[] aesEncryption(byte[] value, byte[] keyData, byte[] ivData) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(ivData);
        SecretKeySpec skeySpec = new SecretKeySpec(keyData, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(1, skeySpec, iv);
        byte[] encrypted = cipher.doFinal(value);
        return encrypted;
    }

    public static byte[] aesDecryption(byte[] encrypted, byte[] keyData, byte[] ivData) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(ivData);
        SecretKeySpec skeySpec = new SecretKeySpec(keyData, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(2, skeySpec, iv);
        byte[] original = cipher.doFinal(encrypted);
        return original;
    }

    public static byte[] rsaEncryption(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(1, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] rsaDecryption(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(2, privateKey);
        return cipher.doFinal(data);
    }

    public static PublicKey getPublicKey(byte[] encoded) {
        PublicKey pubKeyString = null;
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pubKeyString = kf.generatePublic(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return pubKeyString;
    }

    public static byte[] calcHmacSha256(byte[] secretKey, byte[] message) {
        byte[] hmacSha256 = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HmacSHA256");
            mac.init(secretKeySpec);
            hmacSha256 = mac.doFinal(message);
        } catch (Exception e) {
            throw new RuntimeException("Failed to calculate hmac-sha256", e);
        }
        return hmacSha256;
    }

    public static X509CRL generateX509CrlObject(byte[] crlData) {
        X509CRL x509crl = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            x509crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(crlData));
        } catch (Exception e) {
            e.printStackTrace();

                LOG.error("Error while construct X509CRL object. Details: " + Utils.printStackTrace(e));
        }
        return x509crl;
    }

    public static boolean hasRelationship(X509Certificate child, X509Certificate parent) {
        try {
            child.verify(parent.getPublicKey());
            return true;
        } catch (Exception exception) {
            return false;
        }
    }

    public static boolean hasIdPkixOcspNoCheckExtension(X509Certificate certificate) {
        byte[] extensionValue = certificate.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId());
        if (extensionValue != null)
            try {
                ASN1Primitive derObject = toASN1Primitive(extensionValue);
                if (derObject instanceof DEROctetString)
                    return isDEROctetStringNull((DEROctetString)derObject);
            } catch (Exception e) {
                e.printStackTrace();
            }
        return false;
    }

    private static <T extends ASN1Primitive> T toASN1Primitive(byte[] bytes) {
        try {
            return (T)ASN1Primitive.fromByteArray(bytes);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static boolean isDEROctetStringNull(DEROctetString derOctetString) {
        byte[] derOctetStringBytes = derOctetString.getOctets();
        ASN1Primitive asn1Null = toASN1Primitive(derOctetStringBytes);
        return DERNull.INSTANCE.equals(asn1Null);
    }

    public static boolean isCRLExpired(byte[] crlData) {
        X509CRL x509CRL = generateX509CrlObject(crlData);
        if (x509CRL != null) {
            Date now = Calendar.getInstance().getTime();
            Date nextUpdate = x509CRL.getNextUpdate();
            if (nextUpdate.before(now))
                return true;
        }
        return false;
    }

    public static X509Certificate getOcspSigner(BasicOCSPResp basicResponse) {
        X509Certificate ocspSigner = null;
        try {
            if (basicResponse == null) {

                    LOG.error("BasicOCSPResp is NULL or EMPTY");
                return null;
            }
            X509CertificateHolder[] x509CertificateHolder = basicResponse.getCerts();
            int i = 0;
            if (i < x509CertificateHolder.length) {
                X509Certificate certOcspResp = (new JcaX509CertificateConverter()).setProvider("BC").getCertificate(x509CertificateHolder[i]);
                return certOcspResp;
            }
        } catch (Exception e) {
            e.printStackTrace();

                LOG.error("Error while getting OCSP Signer. Details: " + Utils.printStackTrace(e));
        }
        return ocspSigner;
    }
}

