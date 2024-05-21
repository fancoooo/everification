package fpt.signature.sign.general;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IPRestrictionList {
    private List<AttributeIP> attributes;

    @JsonProperty("attributes")
    public List<AttributeIP> getAttributes() {
        return attributes;
    }

    public void setAttributes(List<AttributeIP> attributes) {
        this.attributes = attributes;
    }

    @JsonIgnore
    public List<String> getIpAddress() {
        List<String> ipAddr = new ArrayList<>();
        if (this.attributes != null)
            for (AttributeIP attribute : this.attributes)
                ipAddr.add(attribute.getIp());
        return ipAddr;
    }
}
