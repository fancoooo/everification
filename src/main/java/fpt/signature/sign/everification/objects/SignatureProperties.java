package fpt.signature.sign.everification.objects;


import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import fpt.signature.sign.everification.objects.Rectangle;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SignatureProperties {
    public static final String TYPE_VISIABLE = "VISIBLE_SIGNATURE";

    public static final String TYPE_INVISIABLE = "INVISIBLE_SIGNATURE";

    @JsonIgnore
    private String name;

    private String type;

    private int page;

    private Rectangle rectangle;

    public SignatureProperties(String name, int page, Rectangle rectangle) {
        if (rectangle.getLlx() == 0.0F && rectangle
                .getLly() == 0.0F && rectangle
                .getUrx() == 0.0F && rectangle
                .getUry() == 0.0F) {
            this.type = "INVISIBLE_SIGNATURE";
        } else {
            this.type = "VISIBLE_SIGNATURE";
        }
        this.page = page;
        this.rectangle = rectangle;
        this.name = name;
    }

    public SignatureProperties(int page, Rectangle rectangle) {
        if (rectangle.getLlx() == 0.0F && rectangle
                .getLly() == 0.0F && rectangle
                .getUrx() == 0.0F && rectangle
                .getUry() == 0.0F) {
            this.type = "INVISIBLE_SIGNATURE";
        } else {
            this.type = "VISIBLE_SIGNATURE";
        }
        this.page = page;
        this.rectangle = rectangle;
    }

    @JsonProperty("type")
    public String getType() {
        return this.type;
    }

    public void setType(String type) {
        this.type = type;
    }

    @JsonProperty("page")
    public int getPage() {
        return this.page;
    }

    public void setPage(int page) {
        this.page = page;
    }

    @JsonProperty("rectangle")
    public Rectangle getRectangle() {
        return this.rectangle;
    }

    public void setRectangle(Rectangle rectangle) {
        this.rectangle = rectangle;
    }

    @JsonIgnore
    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
