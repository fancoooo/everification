package fpt.signature.sign.general;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthPropertiesJSNObject {
    private String text;
    private String Access;
    private String keyPrivate;
    private String keyPublic;
    @JsonProperty("text")
    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }
    @JsonProperty("access")
    public String getAccess() {
        return Access;
    }

    public void setAccess(String access) {
        Access = access;
    }

    @JsonProperty("privateKey")
    public String getKeyPrivate() {
        return keyPrivate;
    }

    public void setKeyPrivate(String keyPrivate) {
        this.keyPrivate = keyPrivate;
    }

    @JsonProperty("publicKey")
    public String getKeyPublic() {
        return keyPublic;
    }

    public void setKeyPublic(String keyPublic) {
        this.keyPublic = keyPublic;
    }
}
