package fpt.signature.sign.everification.revocation;

import java.io.Serializable;
import java.security.cert.X509CRL;
import java.util.Date;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;

public class ValidationResp implements Serializable {
    public static final int FAILED_TO_CHECK = -1;

    public static final int GOOD = 0;

    public static final int REVOKED = 1;

    public static final int UNKNOWN = 2;

    public static final int INVALID_CERT = 3;

    private int responseCode;

    private byte[] ocspResponseData;

    private byte[] crlResponseData;

    private String responseMessage;

    private String billCode;

    private Date timestamp;

    private long logInstance;

    private int revocationStatus;

    private Date revocationDt;

    private Date crlEffectiveDt;

    private BasicOCSPResp basicOCSPResp;

    private X509CRL x509Crl;

    private boolean expiredCrl;

    private boolean ocspSignerCertHasHasNoCheckExtension;

    public ValidationResp() {}

    public ValidationResp(int responseCode) {
        this.responseCode = responseCode;
    }

    public ValidationResp(int responseCode, int revocationStatus) {
        this.responseCode = responseCode;
        this.revocationStatus = revocationStatus;
    }

    public ValidationResp(int responseCode, int revocationStatus, Date revocationDt) {
        this.responseCode = responseCode;
        this.revocationStatus = revocationStatus;
        this.revocationDt = revocationDt;
    }

    public int getResponseCode() {
        return this.responseCode;
    }

    public void setResponseCode(int responseCode) {
        this.responseCode = responseCode;
    }

    public byte[] getOcspResponseData() {
        return this.ocspResponseData;
    }

    public void setOcspResponseData(byte[] ocspResponseData) {
        this.ocspResponseData = ocspResponseData;
    }

    public String getResponseMessage() {
        return this.responseMessage;
    }

    public void setResponseMessage(String responseMessage) {
        this.responseMessage = responseMessage;
    }

    public String getBillCode() {
        return this.billCode;
    }

    public void setBillCode(String billCode) {
        this.billCode = billCode;
    }

    public Date getTimestamp() {
        return this.timestamp;
    }

    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }

    public long getLogInstance() {
        return this.logInstance;
    }

    public void setLogInstance(long logInstance) {
        this.logInstance = logInstance;
    }

    public int getRevocationStatus() {
        return this.revocationStatus;
    }

    public void setRevocationStatus(int revocationStatus) {
        this.revocationStatus = revocationStatus;
    }

    public Date getRevocationDt() {
        return this.revocationDt;
    }

    public void setRevocationDt(Date revocationDt) {
        this.revocationDt = revocationDt;
    }

    public byte[] getCrlResponseData() {
        return this.crlResponseData;
    }

    public void setCrlResponseData(byte[] crlResponseData) {
        this.crlResponseData = crlResponseData;
    }

    public BasicOCSPResp getBasicOCSPResp() {
        return this.basicOCSPResp;
    }

    public void setBasicOCSPResp(BasicOCSPResp basicOCSPResp) {
        this.basicOCSPResp = basicOCSPResp;
    }

    public X509CRL getX509Crl() {
        return this.x509Crl;
    }

    public void setX509Crl(X509CRL x509Crl) {
        this.x509Crl = x509Crl;
    }

    public boolean isExpiredCrl() {
        return this.expiredCrl;
    }

    public void setExpiredCrl(boolean expiredCrl) {
        this.expiredCrl = expiredCrl;
    }

    public boolean isOcspSignerCertHasHasNoCheckExtension() {
        return this.ocspSignerCertHasHasNoCheckExtension;
    }

    public void setOcspSignerCertHasHasNoCheckExtension(boolean ocspSignerCertHasHasNoCheckExtension) {
        this.ocspSignerCertHasHasNoCheckExtension = ocspSignerCertHasHasNoCheckExtension;
    }

    public Date getCrlEffectiveDt() {
        return this.crlEffectiveDt;
    }

    public void setCrlEffectiveDt(Date crlEffectiveDt) {
        this.crlEffectiveDt = crlEffectiveDt;
    }
}

