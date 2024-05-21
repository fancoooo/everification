package fpt.signature.sign.object;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import fpt.signature.sign.general.RelyingParty;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class InternalResponse {
    private int status;

    private RelyingParty rp;

    @JsonIgnore
    public RelyingParty getRp() {
        return rp;
    }

    public void setRp(RelyingParty rp) {
        this.rp = rp;
    }

    private String message;

    private String access_token;
    private String token_type;

    public String getAccess_token() {
        return access_token;
    }

    public void setAccess_token(String access_token) {
        this.access_token = access_token;
    }

    public String getToken_type() {
        return token_type;
    }

    public void setToken_type(String token_type) {
        this.token_type = token_type;
    }
    @JsonInclude(JsonInclude.Include.NON_DEFAULT)
    public int getExpires_in() {
        return expires_in;
    }

    public void setExpires_in(int expires_in) {
        this.expires_in = expires_in;
    }

    private int expires_in;

    public InternalResponse(int status, String message, RelyingParty rp) {
        this.status = status;
        this.message = message;
        this.rp = rp;
    }


    public InternalResponse(int status, String message, String access_token, String token_type, int expires_in, RelyingParty rp) {
        this.status = status;
        this.message = message;
        this.token_type = token_type;
        this.access_token = access_token;
        this.expires_in = expires_in;
        this.rp = rp;
    }


    public InternalResponse() {}
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



}
