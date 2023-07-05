package keystore;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class KeyAndCertChain {
    public PrivateKey getmPrivateKey() {
        return mPrivateKey;
    }

    public void setmPrivateKey(PrivateKey mPrivateKey) {
        this.mPrivateKey = mPrivateKey;
    }

    public X509Certificate getmCertificate() {
        return mCertificate;
    }

    public void setmCertificate(Certificate Certificate) {
        this.mCertificate = (X509Certificate) Certificate;
    }

    public X509Certificate[] getmCertificateChain() {
        return mCertificateChain;
    }

    public void setmCertificateChain(Certificate[] CertificateChain) {
        this.mCertificateChain = new X509Certificate[CertificateChain.length];
        for (int i = 0; i < mCertificateChain.length; i++) {
            mCertificateChain[i] = (X509Certificate) CertificateChain[i];
        }
    }

    private PrivateKey mPrivateKey;

    private X509Certificate mCertificate;

    private X509Certificate[] mCertificateChain;
}
