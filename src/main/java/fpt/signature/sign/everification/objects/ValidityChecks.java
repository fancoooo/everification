package fpt.signature.sign.everification.objects;


import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ValidityChecks {
    public static final String STATUS_CERT_NOT_YET_VALID_AT_SIGN_TIME = "CERT_NOT_YET_VALID_AT_SIGN_TIME";

    public static final String STATUS_CERT_EXPIRED_AT_SIGN_TIME = "CERT_EXPIRED_AT_SIGN_TIME";

    public static final String STATUS_CERT_VALID_AT_SIGN_TIME = "CERT_VALID_AT_SIGN_TIME";

    public static final String STATUS_NO_SIGN_TIME = "VALIDITY_NO_SIGNING_TIME_CHECK";

    public static final String STATUS_CERT_NOT_YET_VALID_AT_CHECK_TIME = "CERT_NOT_YET_VALID_AT_CHECK_TIME";

    public static final String STATUS_CERT_EXPIRED_AT_CHECK_TIME = "CERT_EXPIRED_AT_CHECK_TIME";

    public static final String STATUS_CERT_VALID_AT_CHECK_TIME = "CERT_VALID_AT_CHECK_TIME";

    private boolean success;

    private String status;
    @JsonIgnore
    private String statusAtPresent;
    @JsonIgnore
    private String description;
    @JsonIgnore
    private boolean signPurpose;

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

    //@JsonProperty("status_at_present")
    @JsonIgnore
    public String getStatusAtPresent() {
        return this.statusAtPresent;
    }

    public void setStatusAtPresent(String statusAtPresent) {
        this.statusAtPresent = statusAtPresent;
    }

    //@JsonProperty("description")
    @JsonIgnore
    public String getDescription() {
        return this.description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    //@JsonProperty("signing_purpose")
    @JsonIgnore
    public boolean isSignPurpose() {
        return this.signPurpose;
    }

    public void setSignPurpose(boolean signPurpose) {
        this.signPurpose = signPurpose;
    }
}

