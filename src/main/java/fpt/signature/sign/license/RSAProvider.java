package fpt.signature.sign.license;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.JCEECPrivateKey;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;

public class RSAProvider {
    private static final Logger LOG = Logger.getLogger(RSAProvider.class);
    private static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";

    public static byte[] encrypt(byte[] plain, PublicKey pubKey) {
        Cipher cipher = null;

        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(1, pubKey);
        } catch (NoSuchAlgorithmException var24) {
            var24.printStackTrace();
        } catch (NoSuchPaddingException var25) {
            var25.printStackTrace();
        } catch (InvalidKeyException var26) {
            var26.printStackTrace();
        }

        int blockSize = getKeyLength(pubKey) / 8 - 11;
        byte[] block = new byte[blockSize];
        ByteArrayInputStream inStream = new ByteArrayInputStream(plain);
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        Exception ex = null;
        byte[] decryptedBytes = null;

        try {
            for(; inStream.read(block) > -1; block = new byte[blockSize]) {
                try {
                    byte[] decryptedBlock = cipher.doFinal(block);
                    outStream.write(decryptedBlock);
                } catch (IllegalBlockSizeException var27) {
                    ex = var27;
                    LOG.error("IllegalBlockSizeException: " + var27.getMessage());
                    break;
                } catch (BadPaddingException var28) {
                    ex = var28;
                    LOG.error("BadPaddingException: " + var28.getMessage());
                    break;
                } catch (IOException var29) {
                    ex = var29;
                    LOG.error("IOException: " + var29.getMessage());
                    break;
                }
            }

            decryptedBytes = outStream.toByteArray();
        } catch (IOException var30) {
            ex = var30;
            LOG.error("IOException_before_why: " + var30.getMessage());
        } finally {
            try {
                inStream.close();
                outStream.close();
            } catch (IOException var23) {
            }

        }

        if (ex != null) {
            LOG.error("Cannot decrypt data");
        }

        return decryptedBytes;
    }

    public static byte[] decrypt(byte[] encrypted, PrivateKey privKey) {
        Cipher cipher = null;

        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(2, privKey);
        } catch (NoSuchAlgorithmException var24) {
            LOG.error("NoSuchAlgorithmException: " + var24.getMessage());
        } catch (NoSuchPaddingException var25) {
            LOG.error("NoSuchPaddingException: " + var25.getMessage());
        } catch (InvalidKeyException var26) {
            LOG.error("InvalidKeyException: " + var26.getMessage());
        }

        int blockSize = getKeyLength(privKey) / 8;
        byte[] block = new byte[blockSize];
        ByteArrayInputStream inStream = new ByteArrayInputStream(encrypted);
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        Exception ex = null;
        byte[] decryptedBytes = null;
        boolean var9 = false;

        try {
            while(inStream.read(block) > -1) {
                try {
                    byte[] decryptedBlock = cipher.doFinal(block);
                    outStream.write(decryptedBlock);
                } catch (IllegalBlockSizeException var27) {
                    ex = var27;
                    LOG.error("IllegalBlockSizeException: " + var27.getMessage());
                    break;
                } catch (BadPaddingException var28) {
                    ex = var28;
                    LOG.error("BadPaddingException: " + var28.getMessage());
                    break;
                }
            }

            decryptedBytes = outStream.toByteArray();
        } catch (IOException var29) {
            ex = var29;
            LOG.error("IOException_before_why: " + var29.getMessage());
        } finally {
            try {
                inStream.close();
                outStream.close();
            } catch (IOException var23) {
            }

        }

        if (ex != null) {
            LOG.error("Cannot decrypt data");
        }

        return decryptedBytes;
    }

    private static int getKeyLength(PublicKey pk) {
        int keyLength = -1;
        if (pk instanceof RSAPublicKey) {
            keyLength = ((RSAPublicKey)pk).getModulus().bitLength();
        } else if (pk instanceof JCEECPublicKey) {
            ECParameterSpec param = ((JCEECPublicKey)pk).getParameters();
            keyLength = param != null ? param.getN().bitLength() : 0;
        } else if (pk instanceof ECPublicKey) {
            java.security.spec.ECParameterSpec params = ((ECPublicKey)pk).getParams();
            keyLength = params != null ? params.getOrder().bitLength() : 0;
        } else if (pk instanceof DSAPublicKey) {
            DSAParams params = ((DSAPublicKey)pk).getParams();
            keyLength = params != null ? params.getP().bitLength() : ((DSAPublicKey)pk).getY().bitLength();
        }

        return keyLength;
    }

    private static int getKeyLength(PrivateKey pk) {
        int keyLength = -1;
        if (pk instanceof RSAPrivateKey) {
            keyLength = ((RSAPrivateKey)pk).getModulus().bitLength();
        } else if (pk instanceof JCEECPrivateKey) {
            ECParameterSpec param = ((JCEECPrivateKey)pk).getParameters();
            keyLength = param != null ? param.getN().bitLength() : 0;
        } else if (pk instanceof ECPrivateKey) {
            java.security.spec.ECParameterSpec params = ((ECPrivateKey)pk).getParams();
            keyLength = params != null ? params.getOrder().bitLength() : 0;
        } else if (pk instanceof DSAPrivateKey) {
            DSAParams params = ((DSAPrivateKey)pk).getParams();
            keyLength = params != null ? params.getP().bitLength() : ((DSAPrivateKey)pk).getX().bitLength();
        }

        return keyLength;
    }

    private static int getKeyLength(Key key) {
        if (key instanceof PublicKey) {
            PublicKey pk = (PublicKey)key;
            return getKeyLength(pk);
        } else if (key instanceof PrivateKey) {
            PrivateKey pk = (PrivateKey)key;
            return getKeyLength(pk);
        } else {
            return -1;
        }
    }
}
