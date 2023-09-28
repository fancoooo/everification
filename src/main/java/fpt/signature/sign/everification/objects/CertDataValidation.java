package fpt.signature.sign.everification.objects;


import java.security.cert.X509CRL;
import java.util.Date;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;

public class CertDataValidation {
    private static final Logger LOG = Logger.getLogger(fpt.signature.sign.everification.objects.CertDataValidation.class);

    private boolean valid;

    private boolean embeddedInSignature;

    private X509CRL crl;

    private BasicOCSPResp basicOCSPResp;

    private Date ocspRespSignedAt;

    public CertDataValidation() {}

    public CertDataValidation(boolean valid, boolean embeddedInSignature, X509CRL crl, BasicOCSPResp basicOCSPResp, Date ocspRespSignedAt) {
        this.valid = valid;
        this.embeddedInSignature = embeddedInSignature;
        this.crl = crl;
        this.basicOCSPResp = basicOCSPResp;
        this.ocspRespSignedAt = ocspRespSignedAt;
    }

    public boolean isValid() {
        return this.valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public boolean isEmbeddedInSignature() {
        return this.embeddedInSignature;
    }

    public void setEmbeddedInSignature(boolean embeddedInSignature) {
        this.embeddedInSignature = embeddedInSignature;
    }

    public X509CRL getCrl() {
        return this.crl;
    }

    public void setCrl(X509CRL crl) {
        this.crl = crl;
    }

    public BasicOCSPResp getBasicOCSPResp() {
        return this.basicOCSPResp;
    }

    public void setBasicOCSPResp(BasicOCSPResp basicOCSPResp) {
        this.basicOCSPResp = basicOCSPResp;
    }

    public Date getOcspRespSignedAt() {
        return this.ocspRespSignedAt;
    }

    public void setOcspRespSignedAt(Date ocspRespSignedAt) {
        this.ocspRespSignedAt = ocspRespSignedAt;
    }
}

