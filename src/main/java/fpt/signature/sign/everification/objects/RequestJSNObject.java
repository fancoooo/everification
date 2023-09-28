package fpt.signature.sign.everification.objects;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;


@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RequestJSNObject {
    private String data;

    private String encoding;

    private String signature;

    private String signatureFormat;

    private String signatureAlgorithm;

    private boolean signerInformation;

    private boolean certificatesInformation;

    private boolean registeredConstraint;

    private boolean signedDataRequired;

    private String signingTimeTagName;

    private String signingTimeFormat;

    private String document;

    private String password;

    private String username;

    private String personalName;

    private String firstName;

    private String lastName;

    private String organization;

    private String identification;

    private String identificationType;

    private String email;

    private String phone;

    private String ownerID;

    private String certificate;

    private String sharedMode;

    private String agreementID;

    private String serialNumber;

    private String certificateID;

    private String challengeType;

    private String emailSubject;

    private String emailContent;

    private String mobileMessage;

    private String type;

    private String otp;

    private String transactionID;

    boolean emailVerified;

    boolean phoneVerified;

    private String twoFactorMethod;

    private String dob;

    private String doe;

    private boolean ltvEnabled;

    private String paJwt;

    private String faceMatchingJwt;

    private String fingerprintVerificationJwt;

    private String transactionData;

    @JsonProperty("data")
    public String getData() {
        return this.data;
    }

    public void setData(String data) {
        this.data = data;
    }

    @JsonProperty("encoding")
    public String getEncoding() {
        return this.encoding;
    }

    public void setEncoding(String encoding) {
        this.encoding = encoding;
    }

    @JsonProperty("signature")
    public String getSignature() {
        return this.signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    @JsonProperty("signer_information")
    public boolean getSignerInformation() {
        return this.signerInformation;
    }

    public void setSignerInformation(boolean signerInformation) {
        this.signerInformation = signerInformation;
    }

    @JsonProperty("certificates_information")
    public boolean getCertificatesInformation() {
        return this.certificatesInformation;
    }

    public void setCertificatesInformation(boolean certificatesInformation) {
        this.certificatesInformation = certificatesInformation;
    }

    @JsonProperty("registered_constraint")
    public boolean getRegisteredConstraint() {
        return this.registeredConstraint;
    }

    public void setRegisteredConstraint(boolean registeredConstraint) {
        this.registeredConstraint = registeredConstraint;
    }

    @JsonProperty("signed_data_required")
    public boolean getSignedDataRequired() {
        return this.signedDataRequired;
    }

    public void setSignedDataRequired(boolean signedDataRequired) {
        this.signedDataRequired = signedDataRequired;
    }

    @JsonProperty("document")
    public String getDocument() {
        return this.document;
    }

    public void setDocument(String document) {
        this.document = document;
    }

    @JsonProperty("password")
    public String getPassword() {
        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @JsonProperty("personal_name")
    public String getPersonalName() {
        return this.personalName;
    }

    public void setPersonalName(String personalName) {
        this.personalName = personalName;
    }

    @JsonProperty("organization")
    public String getOrganization() {
        return this.organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    @JsonProperty("identification")
    public String getIdentification() {
        return this.identification;
    }

    public void setIdentification(String identification) {
        this.identification = identification;
    }

    @JsonProperty("identification_type")
    public String getIdentificationType() {
        return this.identificationType;
    }

    public void setIdentificationType(String identificationType) {
        this.identificationType = identificationType;
    }

    @JsonProperty("email")
    public String getEmail() {
        return this.email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @JsonProperty("phone")
    public String getPhone() {
        return this.phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    @JsonProperty("username")
    public String getUsername() {
        return this.username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @JsonProperty("owner_id")
    public String getOwnerID() {
        return this.ownerID;
    }

    public void setOwnerID(String ownerID) {
        this.ownerID = ownerID;
    }

    @JsonProperty("certificate")
    public String getCertificate() {
        return this.certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    @JsonProperty("shared_mode")
    public String getSharedMode() {
        return this.sharedMode;
    }

    public void setSharedMode(String sharedMode) {
        this.sharedMode = sharedMode;
    }

    @JsonProperty("agreement_id")
    public String getAgreementID() {
        return this.agreementID;
    }

    public void setAgreementID(String agreementID) {
        this.agreementID = agreementID;
    }

    @JsonProperty("serialnumber")
    public String getSerialNumber() {
        return this.serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    @JsonProperty("certificate_id")
    public String getCertificateID() {
        return this.certificateID;
    }

    public void setCertificateID(String certificateID) {
        this.certificateID = certificateID;
    }

    @JsonProperty("challenge_type")
    public String getChallengeType() {
        return this.challengeType;
    }

    public void setChallengeType(String challengeType) {
        this.challengeType = challengeType;
    }

    @JsonProperty("email_subject")
    public String getEmailSubject() {
        return this.emailSubject;
    }

    public void setEmailSubject(String emailSubject) {
        this.emailSubject = emailSubject;
    }

    @JsonProperty("email_content")
    public String getEmailContent() {
        return this.emailContent;
    }

    public void setEmailContent(String emailContent) {
        this.emailContent = emailContent;
    }

    @JsonProperty("mobile_message")
    public String getMobileMessage() {
        return this.mobileMessage;
    }

    public void setMobileMessage(String mobileMessage) {
        this.mobileMessage = mobileMessage;
    }

    @JsonProperty("signature_format")
    public String getSignatureFormat() {
        return this.signatureFormat;
    }

    public void setSignatureFormat(String signatureFormat) {
        this.signatureFormat = signatureFormat;
    }

    @JsonProperty("signature_algorithm")
    public String getSignatureAlgorithm() {
        return this.signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    @JsonProperty("type")
    public String getType() {
        return this.type;
    }

    public void setType(String type) {
        this.type = type;
    }

    @JsonProperty("otp")
    public String getOtp() {
        return this.otp;
    }

    public void setOtp(String otp) {
        this.otp = otp;
    }

    @JsonProperty("transaction_id")
    public String getTransactionID() {
        return this.transactionID;
    }

    public void setTransactionID(String transactionID) {
        this.transactionID = transactionID;
    }

    @JsonProperty("signing_time_tag_name")
    public String getSigningTimeTagName() {
        return this.signingTimeTagName;
    }

    public void setSigningTimeTagName(String signingTimeTagName) {
        this.signingTimeTagName = signingTimeTagName;
    }

    @JsonProperty("signing_time_format")
    public String getSigningTimeFormat() {
        return this.signingTimeFormat;
    }

    public void setSigningTimeFormat(String signingTimeFormat) {
        this.signingTimeFormat = signingTimeFormat;
    }

    @JsonProperty("email_verified")
    public boolean isEmailVerified() {
        return this.emailVerified;
    }

    public void setEmailVerified(boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    @JsonProperty("phone_verified")
    public boolean isPhoneVerified() {
        return this.phoneVerified;
    }

    public void setPhoneVerified(boolean phoneVerified) {
        this.phoneVerified = phoneVerified;
    }

    @JsonProperty("first_name")
    public String getFirstName() {
        return this.firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    @JsonProperty("last_name")
    public String getLastName() {
        return this.lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    @JsonProperty("two_factor_auth_method")
    public String getTwoFactorMethod() {
        return this.twoFactorMethod;
    }

    public void setTwoFactorMethod(String twoFactorMethod) {
        this.twoFactorMethod = twoFactorMethod;
    }

    @JsonProperty("dob")
    public String getDob() {
        return this.dob;
    }

    public void setDob(String dob) {
        this.dob = dob;
    }

    @JsonProperty("doe")
    public String getDoe() {
        return this.doe;
    }

    public void setDoe(String doe) {
        this.doe = doe;
    }

    @JsonProperty("ltv_enabled")
    public boolean isLtvEnabled() {
        return this.ltvEnabled;
    }

    public void setLtvEnabled(boolean ltvEnabled) {
        this.ltvEnabled = ltvEnabled;
    }

    @JsonProperty("pa")
    public String getPaJwt() {
        return this.paJwt;
    }

    public void setPaJwt(String paJwt) {
        this.paJwt = paJwt;
    }

    @JsonProperty("face_matching")
    public String getFaceMatchingJwt() {
        return this.faceMatchingJwt;
    }

    public void setFaceMatchingJwt(String faceMatchingJwt) {
        this.faceMatchingJwt = faceMatchingJwt;
    }

    @JsonProperty("fingerprint_verification")
    public String getFingerprintVerificationJwt() {
        return this.fingerprintVerificationJwt;
    }

    public void setFingerprintVerificationJwt(String fingerprintVerificationJwt) {
        this.fingerprintVerificationJwt = fingerprintVerificationJwt;
    }

    @JsonProperty("transaction_data")
    public String getTransactionData() {
        return this.transactionData;
    }

    public void setTransactionData(String transactionData) {
        this.transactionData = transactionData;
    }
}

