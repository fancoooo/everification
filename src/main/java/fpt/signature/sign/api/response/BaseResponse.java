package fpt.signature.sign.api.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import fpt.signature.sign.object.VerifyResult;

import java.util.List;

@JsonInclude(Include.NON_NULL)
@JsonPropertyOrder({"responseCode", "responseMessage"})
public class BaseResponse {
    @JsonProperty("responseCode")
    private Integer responseCode;

    @JsonProperty("signatureDetail")
    private List<VerifyResult> signatureDetail;

    public List<VerifyResult> getSignatureDetail() {
        return signatureDetail;
    }

    public void setSignatureDetail(List<VerifyResult> signatureDetail) {
        this.signatureDetail = signatureDetail;
    }

    @JsonProperty("error")
    private boolean error;
    @JsonProperty("responseMessage")
    private String responseMessage;

    @JsonProperty("signedFileData")
    private String signedFileData;

    public BaseResponse() {
    }

    public BaseResponse(Integer responseCode, String responseMessage) {
        this.responseCode = responseCode;
        this.responseMessage = responseMessage;
    }

    public Integer getResponseCode() {
        return this.responseCode;
    }

    public void setResponseCode(Integer responseCode) {
        this.responseCode = responseCode;
    }

    public String getResponseMessage() {
        return this.responseMessage;
    }

    public void setResponseMessage(String responseMessage) {
        this.responseMessage = responseMessage;
    }

    public String getSignedFileData() {
        return signedFileData;
    }

    public boolean isError() {
        return error;
    }

    public void setError(boolean error) {
        this.error = error;
    }

    public void setSignedFileData(String signedFileData) {
        this.signedFileData = signedFileData;
    }

    public BaseResponse(Integer responseCode, String responseMessage, String signedFileData) {
        this.responseCode = responseCode;
        this.responseMessage = responseMessage;
        this.signedFileData = signedFileData;
    }
}
