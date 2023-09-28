package fpt.signature.sign.everification.objects;


import java.security.cert.X509Certificate;
import java.util.Date;

public class CertificationAuthority {
    private int certificationAuthorityID;

    private String name;

    private String uri;

    private Date effectiveDate;

    private Date expiredDate;

    private String subjectDn;

    private String pemCertificate;

    private String pemExCertificate;

    private String remark;

    private String remarkEn;

    private CAProperties caProperties;

    private String subjectKeyIdentifier;

    private String issuerKeyIdentifier;

    private String commonName;

    private X509Certificate x509Object;

    public int getCertificationAuthorityID() {
        return this.certificationAuthorityID;
    }

    public void setCertificationAuthorityID(int certificationAuthorityID) {
        this.certificationAuthorityID = certificationAuthorityID;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getUri() {
        return this.uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public Date getEffectiveDate() {
        return this.effectiveDate;
    }

    public void setEffectiveDate(Date effectiveDate) {
        this.effectiveDate = effectiveDate;
    }

    public Date getExpiredDate() {
        return this.expiredDate;
    }

    public void setExpiredDate(Date expiredDate) {
        this.expiredDate = expiredDate;
    }

    public String getRemark() {
        return this.remark;
    }

    public void setRemark(String remark) {
        this.remark = remark;
    }

    public String getRemarkEn() {
        return this.remarkEn;
    }

    public void setRemarkEn(String remarkEn) {
        this.remarkEn = remarkEn;
    }

    public CAProperties getCaProperties() {
        return this.caProperties;
    }

    public void setCaProperties(CAProperties caProperties) {
        this.caProperties = caProperties;
    }

    public String getPemCertificate() {
        return this.pemCertificate;
    }

    public void setPemCertificate(String pemCertificate) {
        this.pemCertificate = pemCertificate;
    }

    public String getSubjectDn() {
        return this.subjectDn;
    }

    public void setSubjectDn(String subjectDn) {
        this.subjectDn = subjectDn;
    }

    public String getPemExCertificate() {
        return this.pemExCertificate;
    }

    public void setPemExCertificate(String pemExCertificate) {
        this.pemExCertificate = pemExCertificate;
    }

    public String getSubjectKeyIdentifier() {
        return this.subjectKeyIdentifier;
    }

    public void setSubjectKeyIdentifier(String subjectKeyIdentifier) {
        this.subjectKeyIdentifier = subjectKeyIdentifier;
    }

    public String getIssuerKeyIdentifier() {
        return this.issuerKeyIdentifier;
    }

    public void setIssuerKeyIdentifier(String issuerKeyIdentifier) {
        this.issuerKeyIdentifier = issuerKeyIdentifier;
    }

    public String getCommonName() {
        return this.commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public X509Certificate getX509Object() {
        return this.x509Object;
    }

    public void setX509Object(X509Certificate x509Object) {
        this.x509Object = x509Object;
    }
}

