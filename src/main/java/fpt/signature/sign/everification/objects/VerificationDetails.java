package fpt.signature.sign.everification.objects;


import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;
import fpt.signature.sign.everification.objects.Rectangle;
import fpt.signature.sign.everification.objects.RevocationChecks;
import fpt.signature.sign.everification.objects.SignatureProperties;
import fpt.signature.sign.everification.objects.ValidityChecks;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VerificationDetails {
    @Expose
    private Boolean integrity;
    @JsonIgnore
    private Boolean certPathValidation;
    @Expose
    private Boolean trustedCertificate;
    @JsonIgnore
    private Boolean registeredChecks;

    @JsonIgnore
    private boolean revocation;
    @Expose
    private boolean validityStatus;
    @Expose
    private RevocationChecks revocationChecks;

    @JsonIgnore
    private ValidityChecks validityChecks;


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

    //@JsonProperty("registered_checks")
    @JsonIgnore
    public Boolean isRegisteredChecks() {
        return this.registeredChecks;
    }

    public void setRegisteredChecks(Boolean registeredChecks) {
        this.registeredChecks = registeredChecks;
    }

    @JsonProperty("revocation")
    public RevocationChecks getRevocationChecks() {
        return this.revocationChecks;
    }

    public void setRevocationChecks(RevocationChecks revocationChecks) {
        this.revocationChecks = revocationChecks;
    }

    //@JsonProperty("validity")
    @JsonIgnore
    public ValidityChecks getValidityChecks() {
        return this.validityChecks;
    }

    public void setValidityChecks(ValidityChecks validityChecks) {
        this.validityChecks = validityChecks;
    }

    @JsonIgnore
    public boolean getRevocation() {
        return revocation;
    }

    //@JsonProperty("revocationStatus")
    @JsonIgnore
    public void setRevocation(boolean revocation) {
        this.revocation = revocation;
    }

    @JsonProperty("validityStatus")
    public boolean getValidity() {
        return validityStatus;
    }


    public void setValidity(boolean validity) {
        this.validityStatus = validity;
    }
}

