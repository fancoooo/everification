package fpt.signature.sign.everification.objects;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Rectangle {
    private float llx;

    private float lly;

    private float urx;

    private float ury;

    public Rectangle(float llx, float lly, float urx, float ury) {
        this.llx = llx;
        this.lly = lly;
        this.urx = urx;
        this.ury = ury;
    }

    @JsonProperty("llx")
    public float getLlx() {
        return this.llx;
    }

    public void setLlx(float llx) {
        this.llx = llx;
    }

    @JsonProperty("lly")
    public float getLly() {
        return this.lly;
    }

    public void setLly(float lly) {
        this.lly = lly;
    }

    @JsonProperty("urx")
    public float getUrx() {
        return this.urx;
    }

    public void setUrx(float urx) {
        this.urx = urx;
    }

    @JsonProperty("ury")
    public float getUry() {
        return this.ury;
    }

    public void setUry(float ury) {
        this.ury = ury;
    }
}

