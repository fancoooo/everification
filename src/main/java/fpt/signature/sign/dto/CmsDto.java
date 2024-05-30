package fpt.signature.sign.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;

public class CmsDto implements Serializable {
    private String lang;
    @JsonProperty("userName")
    private String username;
    @JsonProperty("alias")
    private String alias;
    @JsonProperty("passWord")
    private String password;
    @JsonProperty("refreshToken")
    private String refreshtoken;
    @JsonProperty("emailContract")
    private String email;
    @JsonProperty("phoneContract")
    private String phone;
    @JsonProperty("fullName")
    private String fullname;
    @JsonProperty("persionalID")
    private String persionalID;
    @JsonProperty("relyingParty")
    private String relyingParty;
    @JsonProperty("oldPassword")
    private String oldPassword;
    @JsonProperty("newPassword")
    private String newPassword;
    @JsonProperty("descriptionVn")
    private String description_vn;
    @JsonProperty("descriptionEn")
    private String description_en;
    @JsonProperty("hsmProperties")
    private String hsm_properties;
    @JsonProperty("enabled")
    private Boolean enabled;
    @JsonProperty("name")
    private String name;
    @JsonProperty("ssl2Enabled")
    private Boolean ssl2_enabled;
    @JsonProperty("ssl2Properties")
    private String ss2_properties;
    @JsonProperty("smtpEnabled")
    private Boolean smtp_enabled;
    @JsonProperty("smtpProperties")
    private String smtp_properties;
    @JsonProperty("smsEnabled")
    private Boolean sms_enabled;
    @JsonProperty("smsProperties")
    private String sms_properties;
    @JsonProperty("properties")
    private String properties;
    @JsonProperty("kwkProperties")
    private String kwk_properties;
    @JsonProperty("keyHandle")
    private String key_handle;
    @JsonProperty("hsmProfileId")
    private Long hsm_profile_id;
    private String certificate;
    private Long duration;
    private Long certificateAuthorityID;
    private Long certificateTypeID;
    private String ejbcaEntityName;

    public String getLang() {
        return lang;
    }

    public void setLang(String lang) {
        this.lang = lang;
    }

    public Long getDuration() {
        return duration;
    }

    public void setDuration(Long duration) {
        this.duration = duration;
    }

    public Long getCertificateAuthorityID() {
        return certificateAuthorityID;
    }

    public void setCertificateAuthorityID(Long certificateAuthorityID) {
        this.certificateAuthorityID = certificateAuthorityID;
    }

    public Long getCertificateTypeID() {
        return certificateTypeID;
    }

    public void setCertificateTypeID(Long certificateTypeID) {
        this.certificateTypeID = certificateTypeID;
    }

    public String getEjbcaEntityName() {
        return ejbcaEntityName;
    }

    public void setEjbcaEntityName(String ejbcaEntityName) {
        this.ejbcaEntityName = ejbcaEntityName;
    }

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public String getKwk_properties() {
        return kwk_properties;
    }

    public void setKwk_properties(String kwk_properties) {
        this.kwk_properties = kwk_properties;
    }

    public String getKey_handle() {
        return key_handle;
    }

    public void setKey_handle(String key_handle) {
        this.key_handle = key_handle;
    }

    public Long getHsm_profile_id() {
        return hsm_profile_id;
    }

    public void setHsm_profile_id(Long hsm_profile_id) {
        this.hsm_profile_id = hsm_profile_id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Boolean getSsl2_enabled() {
        return ssl2_enabled;
    }

    public void setSsl2_enabled(Boolean ssl2_enabled) {
        this.ssl2_enabled = ssl2_enabled;
    }

    public String getSs2_properties() {
        return ss2_properties;
    }

    public void setSs2_properties(String ss2_properties) {
        this.ss2_properties = ss2_properties;
    }

    public Boolean getSmtp_enabled() {
        return smtp_enabled;
    }

    public void setSmtp_enabled(Boolean smtp_enabled) {
        this.smtp_enabled = smtp_enabled;
    }

    public String getSmtp_properties() {
        return smtp_properties;
    }

    public void setSmtp_properties(String smtp_properties) {
        this.smtp_properties = smtp_properties;
    }

    public Boolean getSms_enabled() {
        return sms_enabled;
    }

    public void setSms_enabled(Boolean sms_enabled) {
        this.sms_enabled = sms_enabled;
    }

    public String getSms_properties() {
        return sms_properties;
    }

    public void setSms_properties(String sms_properties) {
        this.sms_properties = sms_properties;
    }

    public String getProperties() {
        return properties;
    }

    public void setProperties(String properties) {
        this.properties = properties;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public String getDescription_vn() {
        return description_vn;
    }

    public void setDescription_vn(String description_vn) {
        this.description_vn = description_vn;
    }

    public String getDescription_en() {
        return description_en;
    }

    public void setDescription_en(String description_en) {
        this.description_en = description_en;
    }

    public String getHsm_properties() {
        return hsm_properties;
    }

    public void setHsm_properties(String hsm_properties) {
        this.hsm_properties = hsm_properties;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public String getOldPassword() {
        return oldPassword;
    }
    public void setOldPassword(String oldPassword) {
        this.oldPassword = oldPassword;
    }
    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public String getFullname() {
        return fullname;
    }

    public void setFullname(String fullname) {
        this.fullname = fullname;
    }

    public String getPersionalID() {
        return persionalID;
    }

    public void setPersionalID(String persionalID) {
        this.persionalID = persionalID;
    }

    public String getRelyingParty() {
        return relyingParty;
    }

    public void setRelyingParty(String relyingParty) {
        this.relyingParty = relyingParty;
    }

    public String getRefreshtoken() {
        return refreshtoken;
    }

    public void setRefreshtoken(String refreshtoken) {
        this.refreshtoken = refreshtoken;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
    @JsonProperty("passWord")
    public String getPassword() {
        return password;
    }
    @JsonProperty("passWord")
    public void setPassword(String password) {
        this.password = password;
    }
}

