package fpt.signature.sign.general;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

@JsonIgnoreProperties(
        ignoreUnknown = true
)
@JsonInclude(Include.NON_NULL)
public class AttributeIP {
    private String ip;
    private String remarkEn;
    private String remark;

    @JsonProperty("ip")
    public String getIp() {
        return this.ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    @JsonProperty("remarkEn")
    public String getRemarkEn() {
        return this.remarkEn;
    }

    public void setRemarkEn(String remarkEn) {
        this.remarkEn = remarkEn;
    }

    @JsonProperty("remark")
    public String getRemark() {
        return this.remark;
    }

    public void setRemark(String remark) {
        this.remark = remark;
    }
}

