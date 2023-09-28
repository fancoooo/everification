package fpt.signature.sign.everification.objects;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Endpoint implements Serializable {
    public static final String EP_TYPE_INTERNAL = "INTERNAL_EP";

    public static final String EP_TYPE_EXTERNAL = "EXTERNAL_EP";

    public static final String EP_TYPE_P2P = "P2P";

    private String type;

    private String uuid;

    @JsonProperty("type")
    public String getType() {
        return this.type;
    }

    public void setType(String type) {
        this.type = type;
    }

    @JsonProperty("uuid")
    public String getUuid() {
        return this.uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }
}

