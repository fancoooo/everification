package fpt.signature.sign.everification.objects;


import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.security.cert.X509CRL;
import java.util.Date;

import com.google.gson.annotations.Expose;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RevocationChecks {
    public static final String PROTOCOL_OCSP = "OCSP";

    public static final String PROTOCOL_CRL = "CRL";

    public static final String PROTOCOL_OCSP_CRL = "OCSP/CRL";

    public static final String PROTOCOL_NONE = "NONE";

    public static final String STATUS_GOOD = "GOOD";

    public static final String STATUS_UNKNOWN = "UNKNOWN";

    public static final String STATUS_REVOKED = "REVOKED";

    public static final String STATUS_REVOKED_NO_SIGNING_TIME = "REVOKED_NO_SIGNING_TIME_CHECK";

    public static final String STATUS_FAILED = "FAILED";

    public static final String STATUS_NONE = "NONE";
    @Expose
    private boolean success;
    @Expose
    private String protocol;
    @Expose
    private String status;
    private String statusAtPresent;

    private String description;
    @Expose
    private Date revocationDt;

    @JsonIgnore
    private byte[] ocspResponseData;

    @JsonIgnore
    private BasicOCSPResp basicOCSPResp;

    @JsonIgnore
    private byte[] crlResponseData;

    @JsonIgnore
    private X509CRL x509Crl;

    @JsonIgnore
    private boolean ocspSignerCertHasNoCheckExtension;

    @JsonProperty("success")
    public boolean isSuccess() {
        return this.success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    @JsonProperty("status")
    public String getStatus() {
        return this.status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @JsonProperty("protocol")
    public String getProtocol() {
        return this.protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    @JsonIgnore
    @JsonProperty("description")
    public String getDescription() {
        return this.description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @JsonProperty("timestamp")
    public Date getRevocationDt() {
        return this.revocationDt;
    }

    public void setRevocationDt(Date revocationDt) {
        this.revocationDt = revocationDt;
    }

    @JsonIgnore
    @JsonProperty("status_at_present")
    public String getStatusAtPresent() {
        return this.statusAtPresent;
    }

    public void setStatusAtPresent(String statusAtPresent) {
        this.statusAtPresent = statusAtPresent;
    }

    @JsonIgnore
    public byte[] getOcspResponseData() {
        return this.ocspResponseData;
    }

    public void setOcspResponseData(byte[] ocspResponseData) {
        this.ocspResponseData = ocspResponseData;
    }

    @JsonIgnore
    public byte[] getCrlResponseData() {
        return this.crlResponseData;
    }

    public void setCrlResponseData(byte[] crlResponseData) {
        this.crlResponseData = crlResponseData;
    }

    @JsonIgnore
    public BasicOCSPResp getBasicOCSPResp() {
        return this.basicOCSPResp;
    }

    public void setBasicOCSPResp(BasicOCSPResp basicOCSPResp) {
        this.basicOCSPResp = basicOCSPResp;
    }

    @JsonIgnore
    public X509CRL getX509Crl() {
        return this.x509Crl;
    }

    public void setX509Crl(X509CRL x509Crl) {
        this.x509Crl = x509Crl;
    }

    @JsonIgnore
    public boolean isOcspSignerCertHasNoCheckExtension() {
        return this.ocspSignerCertHasNoCheckExtension;
    }

    public void setOcspSignerCertHasNoCheckExtension(boolean ocspSignerCertHasNoCheckExtension) {
        this.ocspSignerCertHasNoCheckExtension = ocspSignerCertHasNoCheckExtension;
    }
}

