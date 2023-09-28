package fpt.signature.sign.api.request;

import com.fasterxml.jackson.annotation.JsonProperty;

public class OcrRequest {

    @JsonProperty("document_front")
    private String document_front;
    public String getDocument_front() {
        return document_front;
    }

    public void setDocument_front(String document_front) {
        this.document_front = document_front;
    }


}
