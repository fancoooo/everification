package fpt.signature.sign.api.request;

import com.fasterxml.jackson.annotation.JsonProperty;

public class VerifyPDFRequest extends BaseRequest {
    @JsonProperty("fileData")
    private String signingFileData;

    public String getSigningFileData() {
        return signingFileData;
    }

    public void setSigningFileData(String signingFileData) {
        this.signingFileData = signingFileData;
    }
}
