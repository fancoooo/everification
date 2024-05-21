package fpt.signature.sign.general;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(
        ignoreUnknown = true
)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AttributeFunction {
    private String url;
    private String remake;
    private  String remakeEn;

    @JsonProperty("url")
    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    @JsonProperty("remake")
    public String getRemake() {
        return remake;
    }

    public void setRemake(String remake) {
        this.remake = remake;
    }
    @JsonProperty("remakeEn")
    public String getRemakeEn() {
        return remakeEn;
    }

    public void setRemakeEn(String remakeEn) {
        this.remakeEn = remakeEn;
    }
}
