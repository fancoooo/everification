package fpt.signature.sign.everification.objects;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;


@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RequestJSNObject {

    @Expose
    private String document;
    @Expose
    @NotBlank(message = "not found")
    @NotNull
    private String password;
    private String request_bill_code;

    public String getRequest_bill_code() {
        return request_bill_code;
    }

    public void setRequest_bill_code(String request_bill_code) {
        this.request_bill_code = request_bill_code;
    }

    @JsonProperty("document")
    public String getDocument() {
        return this.document;
    }

    public void setDocument(String document) {
        this.document = document;
    }

    @JsonProperty("password")
    @NotBlank(message = "not found")
    @NotNull
    public String getPassword() {
        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

}

