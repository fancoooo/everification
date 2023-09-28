package fpt.signature.sign.everification.objects;

import java.util.Date;

public class CrlData {
    private int crlDataID;

    private int certificationAuthorityID;

    private byte[] blob;

    private Date lastUpdateDt;

    private Date nextUpdateDt;

    private String issuerSubject;

    private String authorityKeyID;

    public int getCrlDataID() {
        return this.crlDataID;
    }

    public void setCrlDataID(int crlDataID) {
        this.crlDataID = crlDataID;
    }

    public int getCertificationAuthorityID() {
        return this.certificationAuthorityID;
    }

    public void setCertificationAuthorityID(int certificationAuthorityID) {
        this.certificationAuthorityID = certificationAuthorityID;
    }

    public byte[] getBlob() {
        return this.blob;
    }

    public void setBlob(byte[] blob) {
        this.blob = blob;
    }

    public Date getLastUpdateDt() {
        return this.lastUpdateDt;
    }

    public void setLastUpdateDt(Date lastUpdateDt) {
        this.lastUpdateDt = lastUpdateDt;
    }

    public Date getNextUpdateDt() {
        return this.nextUpdateDt;
    }

    public void setNextUpdateDt(Date nextUpdateDt) {
        this.nextUpdateDt = nextUpdateDt;
    }

    public String getIssuerSubject() {
        return this.issuerSubject;
    }

    public void setIssuerSubject(String issuerSubject) {
        this.issuerSubject = issuerSubject;
    }

    public String getAuthorityKeyID() {
        return this.authorityKeyID;
    }

    public void setAuthorityKeyID(String authorityKeyID) {
        this.authorityKeyID = authorityKeyID;
    }
}

