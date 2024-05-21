package fpt.signature.sign.everification.objects;


import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Date;

import com.google.gson.annotations.Expose;
import fpt.signature.sign.everification.objects.TSAChecks;
import fpt.signature.sign.everification.objects.VerificationDetails;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ValidityResult {
    public static final String STATUS_SIGNATURE_DELETED = "SIGNATURE_DELETED";

    public static final String STATUS_SIGNATURE_EXISTING = "SIGNATURE_EXISTING";

    public static final String STATUS_SIGNATURE_ERROR = "SIGNATURE_ERROR";
    @JsonIgnore
    private String sigingForm;
    @Expose
    private String signature_name;
    @Expose
    private String signature_algorithm;
    @Expose
    private Date signing_time;
    @JsonIgnore
    private String signedData;
    @Expose
    private Boolean success;
    @Expose
    private VerificationDetails verificationDetails;

    private TSAChecks tsa;
    @Expose
    private Boolean timestampEmbedded;
    @Expose
    private String signer_cn;
    @Expose
    private String issuer_cn;

    private String subject;

    private String issuer;
    @JsonIgnore
    private String thumbprint;
    @Expose
    private String serialNumber;
    @JsonIgnore
    private String keyHash;
    @Expose
    private Date validFrom;
    @Expose
    private Date validTo;

    private String certificate;

    private String[] chains;
    @JsonIgnore
    private String certificateState;
    @JsonIgnore
    private String issuerThumbprint;
    @JsonIgnore
    private String issuerSerialNumber;
    @JsonIgnore
    private String ltvDescription;

    private String status = "SIGNATURE_EXISTING";
    @JsonIgnore
    private String signatureType;

    @JsonIgnore
    private String issuerKeyIdentifier;
    @JsonIgnore
    private String rootCAKeyIdentifier;

    //@JsonProperty("signing_form")
    @JsonIgnore
    public String getSigingForm() {
        return this.sigingForm;
    }

    public void setSigingForm(String sigingForm) {
        this.sigingForm = sigingForm;
    }

    @JsonProperty("signature_name")
    public String getSignatureID() {
        return this.signature_name;
    }

    public void setSignatureID(String signatureID) {
        this.signature_name = signatureID;
    }

    @JsonProperty("signature_algorithm")
    public String getAlgorithm() {
        return this.signature_algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.signature_algorithm = algorithm;
    }

    @JsonProperty("signing_time")
    public Date getSigningTime() {
        return this.signing_time;
    }

    public void setSigningTime(Date signingTime) {
        this.signing_time = signingTime;
    }

    //@JsonProperty("signed_data")
    @JsonIgnore
    public String getSignedData() {
        return this.signedData;
    }

    public void setSignedData(String signedData) {
        this.signedData = signedData;
    }

    @JsonProperty("success")
    public Boolean isSuccess() {
        return this.success;
    }

    public void setSuccess(Boolean success) {
        this.success = success;
    }

    //@JsonProperty("verification_details")
    @JsonProperty("details")
    public VerificationDetails getVerificationDetails() {
        return this.verificationDetails;
    }

    public void setVerificationDetails(VerificationDetails verificationDetails) {
        this.verificationDetails = verificationDetails;
    }

    //@JsonProperty("tsa")
    //@JsonProperty("timestamp")
    @JsonIgnore
    public TSAChecks getTsa() {
        return this.tsa;
    }

    public void setTsa(TSAChecks tsa) {
        this.tsa = tsa;
    }
    @JsonIgnore
    @JsonProperty("subject")
    public String getSubject() {
        return this.subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }
    @JsonIgnore
    @JsonProperty("issuer")
    public String getIssuer() {
        return this.issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    //@JsonProperty("thumbprint")
    @JsonIgnoreProperties
    public String getThumbprint() {
        return this.thumbprint;
    }

    public void setThumbprint(String thumbprint) {
        this.thumbprint = thumbprint;
    }

    @JsonProperty("serialnumber")
    public String getSerialNumber() {
        return this.serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    //@JsonProperty("key_hash")
    @JsonIgnore
    public String getKeyHash() {
        return this.keyHash;
    }

    public void setKeyHash(String keyHash) {
        this.keyHash = keyHash;
    }

    @JsonProperty("valid_from")
    public Date getValidFrom() {
        return this.validFrom;
    }

    public void setValidFrom(Date validFrom) {
        this.validFrom = validFrom;
    }

    @JsonProperty("valid_to")
    public Date getValidTo() {
        return this.validTo;
    }

    public void setValidTo(Date validTo) {
        this.validTo = validTo;
    }

    @JsonProperty("certificate")
    public String getCertificate() {
        return this.certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    @JsonProperty("chains")
    public String[] getChains() {
        return this.chains;
    }

    public void setChains(String[] chains) {
        this.chains = chains;
    }

    @JsonProperty("certificate_state")
    public String getCertificateState() {
        return this.certificateState;
    }

    public void setCertificateState(String certificateState) {
        this.certificateState = certificateState;
    }

    //@JsonProperty("issuer_thumbprint")
    @JsonIgnore
    public String getIssuerThumbprint() {
        return this.issuerThumbprint;
    }

    public void setIssuerThumbprint(String issuerThumbprint) {
        this.issuerThumbprint = issuerThumbprint;
    }

    //@JsonProperty("issuer_serialnumber")
    @JsonIgnore
    public String getIssuerSerialNumber() {
        return this.issuerSerialNumber;
    }

    public void setIssuerSerialNumber(String issuerSerialNumber) {
        this.issuerSerialNumber = issuerSerialNumber;
    }

    //@JsonProperty("status")
    public String getStatus() {
        return this.status;
    }

    public void setStatus(String status) {
        this.status = status;
    }


    //@JsonProperty("ltv_description")
    @JsonIgnore
    public String getLtvDescription() {
        return this.ltvDescription;
    }

    public void setLtvDescription(String ltvDescription) {
        this.ltvDescription = ltvDescription;
    }

    //@JsonProperty("signature_type")
    @JsonIgnore
    public String getSignatureType() {
        return this.signatureType;
    }

    public void setSignatureType(String signatureType) {
        this.signatureType = signatureType;
    }

    //@JsonProperty("issuer_key_identifier")
    @JsonIgnore
    public String getIssuerKeyIdentifier() {
        return this.issuerKeyIdentifier;
    }

    public void setIssuerKeyIdentifier(String issuerKeyIdentifier) {
        this.issuerKeyIdentifier = issuerKeyIdentifier;
    }

    //@JsonProperty("root_ca_key_identifier")
    @JsonIgnore
    public String getRootCAKeyIdentifier() {
        return this.rootCAKeyIdentifier;
    }

    public void setRootCAKeyIdentifier(String rootCAKeyIdentifier) {
        this.rootCAKeyIdentifier = rootCAKeyIdentifier;
    }

    @JsonProperty("timestampEmbedded")
    public Boolean getTimestampEmbedded() {
        return timestampEmbedded;
    }

    public void setTimestampEmbedded(Boolean timestampEmbedded) {
        this.timestampEmbedded = timestampEmbedded;
    }

    @JsonProperty("signer_cn")
    public String getSigner_cn() {
        return signer_cn;
    }

    public void setSigner_cn(String signer_cn) {
        this.signer_cn = signer_cn;
    }

    public String getIssuer_cn() {
        return issuer_cn;
    }
    @JsonProperty("issuer_cn")
    public void setIssuer_cn(String issuer_cn) {
        this.issuer_cn = issuer_cn;
    }
}
