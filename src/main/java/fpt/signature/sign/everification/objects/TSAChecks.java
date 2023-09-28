package fpt.signature.sign.everification.objects;


import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import fpt.signature.sign.everification.objects.RevocationChecks;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TSAChecks {
    private Boolean integrity;
    @JsonIgnore
    private Boolean certPathValidation;

    private Boolean trustedCertificate;

    private RevocationChecks revocationChecks;

    @JsonProperty("integrity")
    public Boolean isIntegrity() {
        return this.integrity;
    }

    public void setIntegrity(Boolean integrity) {
        this.integrity = integrity;
    }

    //@JsonProperty("certpath_validation")
    @JsonIgnore
    public Boolean isCertPathValidation() {
        return this.certPathValidation;
    }

    public void setCertPathValidation(Boolean certPathValidation) {
        this.certPathValidation = certPathValidation;
    }

    //@JsonProperty("trusted_certificate")
    @JsonProperty("trusted")
    public Boolean isTrustedCertificate() {
        return this.trustedCertificate;
    }

    public void setTrustedCertificate(Boolean trustedCertificate) {
        this.trustedCertificate = trustedCertificate;
    }

    @JsonProperty("revocation")
    public RevocationChecks getRevocationChecks() {
        return this.revocationChecks;
    }

    public void setRevocationChecks(RevocationChecks revocationChecks) {
        this.revocationChecks = revocationChecks;
    }
}

