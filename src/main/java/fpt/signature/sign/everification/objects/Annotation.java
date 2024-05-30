package fpt.signature.sign.everification.objects;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Date;

import com.google.gson.annotations.Expose;
import fpt.signature.sign.everification.objects.Rectangle;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Annotation {
    public static final String STATUS_ANNOTATIONS_CREATED = "ANNOTATIONS_CREATED";

    public static final String STATUS_ANNOTATIONS_MODIFIED = "ANNOTATIONS_MODIFIED";
    @Expose
    private String name;
    @Expose
    private String type;
    @Expose
    private int page;
    @Expose
    private Rectangle rectangle;
    @Expose
    private String content;
    @Expose
    private String status;
    @Expose
    private Date createdDt;
    @Expose
    private Date modifiedDt;

    @JsonProperty("name")
    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
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

    @JsonProperty("content")
    public String getContent() {
        return this.content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    @JsonProperty("status")
    public String getStatus() {
        return this.status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    @JsonProperty("created_dt")
    public Date getCreatedDt() {
        return this.createdDt;
    }

    public void setCreatedDt(Date createdDt) {
        this.createdDt = createdDt;
    }

    @JsonProperty("modified_dt")
    public Date getModifiedDt() {
        return this.modifiedDt;
    }

    public void setModifiedDt(Date modifiedDt) {
        this.modifiedDt = modifiedDt;
    }
}

