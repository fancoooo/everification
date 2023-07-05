package fpt.signature.sign.object;

import java.io.Serializable;
import java.util.Date;

public class VerifyResult implements Serializable {
    public String serialNumber;
    public String subjectDN;
    public String issuer;
    public Date expriteDate;
    public Date effectDate;
    private Date signingTime;
    private boolean signatureStatus;
    private String certStatus;
    private String certificate;
    private int signatureIndex = 0;
    private int code;

    public String getSerialNumber() {
        return this.serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getSubjectDN() {
        return this.subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    public String getIssuer() {
        return this.issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public Date getExpriteDate() {
        return this.expriteDate;
    }

    public void setExpriteDate(Date expriteDate) {
        this.expriteDate = expriteDate;
    }

    public Date getEffectDate() {
        return this.effectDate;
    }

    public void setEffectDate(Date effectDate) {
        this.effectDate = effectDate;
    }

    public boolean isSignatureStatus() {
        return this.signatureStatus;
    }

    public void setSignatureStatus(boolean signatureStatus) {
        this.signatureStatus = signatureStatus;
    }

    public void setSignatureIndex(int signatureIndex) {
        this.signatureIndex = signatureIndex;
    }

    public String getCertStatus() {
        return this.certStatus;
    }

    public void setCertStatus(String certStatus) {
        this.certStatus = certStatus;
    }

    public String getCertificate() {
        return this.certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public int getCode() {
        return this.code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public Date getSigningTime() {
        return this.signingTime;
    }

    public void setSigningTime(Date signingTime) {
        this.signingTime = signingTime;
    }
}
