package fpt.signature.sign.api.request;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SignPDFRequest extends BaseRequest {
    @JsonProperty("signingFileData")
    private String signingFileData;

    public String getSigningFileData() {
        return signingFileData;
    }

    public void setSigningFileData(String signingFileData) {
        this.signingFileData = signingFileData;
    }
}
