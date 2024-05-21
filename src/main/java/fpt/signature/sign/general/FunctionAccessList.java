package fpt.signature.sign.general;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FunctionAccessList {
    private List<AttributeFunction> attributes;
    @JsonProperty("attributes")
    public List<AttributeFunction> getAttributes() {
        return attributes;
    }

    public void setAttributes(List<AttributeFunction> attributes) {
        this.attributes = attributes;
    }


    @JsonIgnore
    public List<String> getFunctions() {
        List<String> func = new ArrayList<>();
        if (this.attributes != null)
            for (AttributeFunction attribute : this.attributes)
                func.add(attribute.getUrl());
        return func;
    }
}
