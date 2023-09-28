package fpt.signature.sign.license;

import java.security.cert.Certificate;
import java.util.List;

public class ValidationData {
    private byte[] signedData;
    private byte[] unsignData;
    private List<Certificate> trustAnchors;
    private Certificate[] certChain;
    private int certVerifyMethod;

    public ValidationData(byte[] data, List<Certificate> trustAnchors, int certVerifyMethod) {
        this.signedData = data;
        this.trustAnchors = trustAnchors;
        this.certVerifyMethod = certVerifyMethod;
    }


    public ValidationData() {

    }

    public byte[] getSignedData() {
        return this.signedData;
    }

    public void setSignedData(byte[] signedData) {
        this.signedData = signedData;
    }

    public List<Certificate> getTrustAnchors() {
        return this.trustAnchors;
    }

    public void setTrustAnchors(List<Certificate> trustAnchors) {
        this.trustAnchors = trustAnchors;
    }

    public int getCertVerifyMethod() {
        return this.certVerifyMethod;
    }

    public void setCertVerifyMethod(int certVerifyMethod) {
        this.certVerifyMethod = certVerifyMethod;
    }

    public byte[] getUnsignData() {
        return this.unsignData;
    }

    public void setUnsignData(byte[] unsignData) {
        this.unsignData = unsignData;
    }

    public Certificate[] getCertChain() {
        return this.certChain;
    }

    public void setCertChain(Certificate[] certChain) {
        this.certChain = certChain;
    }
}
