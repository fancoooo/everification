package fpt.signature.sign.general;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VerificationPropertiesJSNObject {
    private Boolean checkOcsp;
    private Boolean checkCrl;
    private int retry;
    private boolean showAnntations;
    private boolean showSignatureError;
    private boolean showSignatureDelete;

    public boolean isShowSignatureError() {
        return showSignatureError;
    }

    public void setShowSignatureError(boolean showSignatureError) {
        this.showSignatureError = showSignatureError;
    }

    public boolean isShowSignatureDelete() {
        return showSignatureDelete;
    }

    public void setShowSignatureDelete(boolean showSignatureDelete) {
        this.showSignatureDelete = showSignatureDelete;
    }

    public boolean isShowAnntations() {
        return showAnntations;
    }

    public void setShowAnntations(boolean showAnntations) {
        this.showAnntations = showAnntations;
    }

    public int getRetry() {
        return retry;
    }

    public void setRetry(int retry) {
        this.retry = retry;
    }

    @JsonProperty("checkOcsp")
    public Boolean getCheckOcsp() {
        return checkOcsp;
    }

    public void setCheckOcsp(Boolean checkOcsp) {
        this.checkOcsp = checkOcsp;
    }

    @JsonProperty("checkCrl")
    public Boolean getCheckCrl() {
        return checkCrl;
    }

    public void setCheckCrl(Boolean checkCrl) {
        this.checkCrl = checkCrl;
    }
}
