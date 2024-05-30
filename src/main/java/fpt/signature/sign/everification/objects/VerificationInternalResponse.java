package fpt.signature.sign.everification.objects;


import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;
import fpt.signature.sign.everification.objects.Annotation;
import fpt.signature.sign.everification.objects.ValidityResult;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VerificationInternalResponse {
    @Expose
    private int status;
    @Expose
    private String message;
    private String response_bill_code;
    @Expose
    private List<ValidityResult> signatures;
    @Expose
    private Annotation[] annotations;

    public VerificationInternalResponse() {}

    public VerificationInternalResponse(int status, String message) {
        this.status = status;
        this.message = message;
    }

    public VerificationInternalResponse(int status, String message, String response_bill_code) {
        this.status = status;
        this.message = message;
        this.response_bill_code = response_bill_code;
    }

    public List<ValidityResult> getSignatures() {
        return signatures;
    }

    public void setSignatures(List<ValidityResult> signatures) {
        this.signatures = signatures;
    }

    public Annotation[] getAnnotations() {
        return annotations;
    }

    public void setAnnotations(Annotation[] annotations) {
        this.annotations = annotations;
    }

    public VerificationInternalResponse(int status) {
        this.status = status;
    }

    public String getResponse_bill_code() {
        return response_bill_code;
    }

    public void setResponse_bill_code(String response_bill_code) {
        this.response_bill_code = response_bill_code;
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
        return signatures;
    }

    public void setValidityResults(List<ValidityResult> validityResults) {
        this.signatures = validityResults;
    }
}
