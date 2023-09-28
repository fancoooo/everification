package fpt.signature.sign.everification.objects;


import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import fpt.signature.sign.everification.objects.Annotation;
import fpt.signature.sign.everification.objects.ValidityResult;

public class VerificationInternalResponse {
    private int status;

    private String message;

    private List<ValidityResult> validityResults;


    public VerificationInternalResponse() {}

    public VerificationInternalResponse(int status, String message) {
        this.status = status;
        this.message = message;
    }

    public VerificationInternalResponse(int status) {
        this.status = status;
    }

    public int getStatus() {
        return this.status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public String getMessage() {
        return this.message;
    }

    public void setMessage(String message) {
        this.message = message;
    }


    @JsonProperty("signatures")
    public List<ValidityResult> getValidityResults() {
        return validityResults;
    }

    public void setValidityResults(List<ValidityResult> validityResults) {
        this.validityResults = validityResults;
    }
}
