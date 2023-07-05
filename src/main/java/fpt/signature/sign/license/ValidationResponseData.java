package fpt.signature.sign.license;

import java.security.cert.X509Certificate;

public class ValidationResponseData {
    private int resutCode;
    private String message;
    private X509Certificate signerCertificate;

    public int getResutCode() {
        return this.resutCode;
    }

    public void setResutCode(int resutCode) {
        this.resutCode = resutCode;
    }

    public String getMessage() {
        return this.message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public X509Certificate getSignerCertificate() {
        return this.signerCertificate;
    }

    public void setSignerCertificate(X509Certificate signerCertificate) {
        this.signerCertificate = signerCertificate;
    }
}
